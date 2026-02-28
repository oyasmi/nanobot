"""DingTalk AI Card channel — streaming replies via interactive cards."""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from loguru import logger
import httpx

from nanobot.bus.events import OutboundMessage
from nanobot.bus.queue import MessageBus
from nanobot.channels.base import BaseChannel
from nanobot.config.schema import DingTalkCardConfig

try:
    from dingtalk_stream import (
        DingTalkStreamClient,
        Credential,
        CallbackHandler,
        CallbackMessage,
        AckMessage,
    )
    from dingtalk_stream.chatbot import ChatbotMessage

    DINGTALK_AVAILABLE = True
except ImportError:
    DINGTALK_AVAILABLE = False
    CallbackHandler = object  # type: ignore[assignment,misc]
    CallbackMessage = None  # type: ignore[assignment,misc]
    AckMessage = None  # type: ignore[assignment,misc]
    ChatbotMessage = None  # type: ignore[assignment,misc]


# ── DingTalk API ────────────────────────────────────────────────────────────

DINGTALK_API = "https://api.dingtalk.com"

# Token refresh threshold (1.5 hours; tokens expire after 2 hours)
_TOKEN_REFRESH_MS = 90 * 60 * 1000


# ── AI Card State ───────────────────────────────────────────────────────────

@dataclass
class AICard:
    """Tracks a single AI Card instance."""

    instance_id: str
    conversation_id: str
    access_token: str
    template_key: str
    created_at: float = field(default_factory=time.time)
    last_updated: float = field(default_factory=time.time)
    content: str = ""       # accumulated content
    finished: bool = False


# ── Stream Handler ──────────────────────────────────────────────────────────

class _CardDingTalkHandler(CallbackHandler):
    """Receive messages via DingTalk Stream and forward to the channel."""

    def __init__(self, channel: "DingTalkCardChannel"):
        super().__init__()
        self.channel = channel

    async def process(self, message: CallbackMessage):
        try:
            chatbot_msg = ChatbotMessage.from_dict(message.data)

            content = ""
            if chatbot_msg.text:
                content = chatbot_msg.text.content.strip()
            if not content and chatbot_msg.rich_text_content:
                # richText: 用户发送了带格式(列表/图文混排)的消息
                parts = []
                for item in chatbot_msg.rich_text_content.rich_text_list or []:
                    if isinstance(item, dict) and "text" in item:
                        parts.append(item["text"])
                content = "\n".join(parts).strip()
            if not content:
                content = message.data.get("text", {}).get("content", "").strip()

            if not content:
                logger.warning(
                    "DingTalk Card: empty message (type={}, keys={})",
                    chatbot_msg.message_type,
                    list(message.data.keys()),
                )
                return AckMessage.STATUS_OK, "OK"

            sender_id = chatbot_msg.sender_staff_id or chatbot_msg.sender_id
            sender_name = chatbot_msg.sender_nick or "Unknown"
            conversation_id = message.data.get("conversationId", "")
            conversation_type = message.data.get("conversationType", "1")

            logger.info(
                "DingTalk Card ← {} ({}): {}", sender_name, sender_id, content,
            )

            task = asyncio.create_task(
                self.channel._on_message(
                    content, sender_id, sender_name,
                    conversation_id, conversation_type,
                )
            )
            self.channel._background_tasks.add(task)
            task.add_done_callback(self.channel._background_tasks.discard)

            return AckMessage.STATUS_OK, "OK"
        except Exception as e:
            logger.error("DingTalk Card handler error: {}", e)
            return AckMessage.STATUS_OK, "Error"


# ── Channel ─────────────────────────────────────────────────────────────────

class DingTalkCardChannel(BaseChannel):
    """DingTalk channel with AI Card streaming replies.

    Uses the same ``dingtalk-stream`` SDK to *receive* messages, but replies
    are delivered through AI interactive cards that support incremental
    (streaming) content updates.
    """

    name = "dingtalk_card"

    def __init__(self, config: DingTalkCardConfig, bus: MessageBus):
        super().__init__(config, bus)
        self.config: DingTalkCardConfig = config
        self._client: Any = None
        self._http: httpx.AsyncClient | None = None

        # Access-token cache
        self._access_token: str | None = None
        self._token_expiry: float = 0

        # Active AI cards: chat_id → AICard
        self._active_cards: dict[str, AICard] = {}

        # Conversation metadata cache: chat_id → {conversation_id, conversation_type, sender_id}
        self._conv_meta: dict[str, dict[str, str]] = {}

        # Background task ref-set (prevent GC)
        self._background_tasks: set[asyncio.Task] = set()

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        if not DINGTALK_AVAILABLE:
            logger.error(
                "dingtalk-stream SDK not installed. Run: pip install dingtalk-stream"
            )
            return

        if not self.config.client_id or not self.config.client_secret:
            logger.error("DingTalk Card: client_id / client_secret not configured")
            return

        if not self.config.card_template_id:
            logger.warning(
                "DingTalk Card: card_template_id not configured — "
                "AI Card streaming will not work"
            )

        self._running = True
        self._http = httpx.AsyncClient()

        logger.info(
            "DingTalk Card: initialising stream (client_id={}…)",
            self.config.client_id[:8],
        )

        credential = Credential(self.config.client_id, self.config.client_secret)
        self._client = DingTalkStreamClient(credential)

        handler = _CardDingTalkHandler(self)
        self._client.register_callback_handler(ChatbotMessage.TOPIC, handler)

        logger.info("DingTalk Card channel started")

        while self._running:
            try:
                await self._client.start()
            except Exception as e:
                logger.warning("DingTalk Card stream error: {}", e)
            if self._running:
                logger.info("DingTalk Card: reconnecting in 5 s …")
                await asyncio.sleep(5)

    async def stop(self) -> None:
        self._running = False
        if self._http:
            await self._http.aclose()
            self._http = None
        for task in self._background_tasks:
            task.cancel()
        self._background_tasks.clear()

    # ── access token ─────────────────────────────────────────────────────

    async def _get_access_token(self) -> str | None:
        if self._access_token and time.time() < self._token_expiry:
            return self._access_token

        if not self._http:
            return None

        try:
            resp = await self._http.post(
                f"{DINGTALK_API}/v1.0/oauth2/accessToken",
                json={
                    "appKey": self.config.client_id,
                    "appSecret": self.config.client_secret,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            self._access_token = data.get("accessToken")
            self._token_expiry = time.time() + int(data.get("expireIn", 7200)) - 60
            return self._access_token
        except Exception as e:
            logger.error("DingTalk Card: failed to get access token: {}", e)
            return None

    # ── AI Card operations ───────────────────────────────────────────────

    async def _create_card(self, chat_id: str) -> AICard | None:
        """Create and deliver an AI Card, return the tracked instance."""
        token = await self._get_access_token()
        if not token:
            return None

        meta = self._conv_meta.get(chat_id, {})
        conversation_id = meta.get("conversation_id", chat_id)
        sender_id = meta.get("sender_id", chat_id)
        # conversationType: "1" = 单聊 (robot DM), "2" = 群聊
        # NOTE: conversationId 即使在单聊中也以 "cid" 开头，不能用前缀判断
        is_group = meta.get("conversation_type") == "2"

        instance_id = f"card_{uuid4()}"
        robot_code = self.config.robot_code or self.config.client_id

        # openSpaceId 格式（参考钉钉官方文档）:
        #   群聊: dtv1.card//IM_GROUP.{openConversationId}
        #   单聊: dtv1.card//IM_ROBOT.{userId}   ← 使用接收者的 userId
        open_space_id = (
            f"dtv1.card//IM_GROUP.{conversation_id}"
            if is_group
            else f"dtv1.card//IM_ROBOT.{sender_id}"
        )

        body: dict[str, Any] = {
            "cardTemplateId": self.config.card_template_id,
            "outTrackId": instance_id,
            "cardData": {"cardParamMap": {}},
            "callbackType": "STREAM",
            "imGroupOpenSpaceModel": {"supportForward": True},
            "imRobotOpenSpaceModel": {"supportForward": True},
            "openSpaceId": open_space_id,
            "userIdType": 1,
        }

        if is_group:
            body["imGroupOpenDeliverModel"] = {"robotCode": robot_code}
        else:
            body["imRobotOpenDeliverModel"] = {"spaceType": "IM_ROBOT"}

        try:
            resp = await self._http.post(  # type: ignore[union-attr]
                f"{DINGTALK_API}/v1.0/card/instances/createAndDeliver",
                json=body,
                headers={
                    "x-acs-dingtalk-access-token": token,
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error(
                "DingTalk Card: create failed ({}): {}",
                e.response.status_code, e.response.text,
            )
            return None
        except Exception as e:
            logger.error("DingTalk Card: create failed: {}", e)
            return None

        card = AICard(
            instance_id=instance_id,
            conversation_id=conversation_id,
            access_token=token,
            template_key=self.config.card_template_key,
        )
        self._active_cards[chat_id] = card
        return card

    async def _stream_card(
        self, card: AICard, content: str, *, finalize: bool = False,
    ) -> bool:
        """Push a full-replacement streaming update to an AI Card."""
        # Refresh token if needed
        age_ms = (time.time() - card.created_at) * 1000
        if age_ms > _TOKEN_REFRESH_MS:
            token = await self._get_access_token()
            if token:
                card.access_token = token

        body = {
            "outTrackId": card.instance_id,
            "guid": str(uuid4()),
            "key": card.template_key,
            "content": content,
            "isFull": True,
            "isFinalize": finalize,
            "isError": False,
        }

        try:
            resp = await self._http.put(  # type: ignore[union-attr]
                f"{DINGTALK_API}/v1.0/card/streaming",
                json=body,
                headers={
                    "x-acs-dingtalk-access-token": card.access_token,
                    "Content-Type": "application/json",
                },
            )
            resp.raise_for_status()
            card.last_updated = time.time()
            card.content = content
            if finalize:
                card.finished = True
            return True
        except httpx.HTTPStatusError as e:
            logger.error(
                "DingTalk Card: streaming failed ({}): {}",
                e.response.status_code, e.response.text,
            )
            return False
        except Exception as e:
            logger.error("DingTalk Card: streaming failed: {}", e)
            return False

    # ── send (outbound dispatch) ─────────────────────────────────────────

    async def send(self, msg: OutboundMessage) -> None:
        is_progress = msg.metadata.get("_progress", False)
        chat_id = msg.chat_id

        card = self._active_cards.get(chat_id)

        if is_progress:
            # ── progress message → update existing card ──────────────
            if card is None or card.finished:
                # Card not ready yet (unlikely) or already finished — drop
                return
            separator = "\n\n" if card.content else ""
            new_content = f"{card.content}{separator}⏳ {msg.content}"
            await self._stream_card(card, new_content)
        else:
            # ── final message → finalize card or fallback ────────────
            if card is not None and not card.finished:
                await self._stream_card(card, msg.content, finalize=True)
                self._active_cards.pop(chat_id, None)
            else:
                # No card — fallback to plain robot message
                await self._send_plain(msg)

    async def _send_plain(self, msg: OutboundMessage) -> None:
        """Fallback: send via robot oToMessages API (non-streaming)."""
        token = await self._get_access_token()
        if not token or not self._http:
            return

        try:
            resp = await self._http.post(
                f"{DINGTALK_API}/v1.0/robot/oToMessages/batchSend",
                json={
                    "robotCode": self.config.robot_code or self.config.client_id,
                    "userIds": [msg.chat_id],
                    "msgKey": "sampleMarkdown",
                    "msgParam": json.dumps(
                        {"text": msg.content, "title": "Nanobot"},
                        ensure_ascii=False,
                    ),
                },
                headers={
                    "x-acs-dingtalk-access-token": token,
                    "Content-Type": "application/json",
                },
            )
            if resp.status_code != 200:
                logger.error("DingTalk Card fallback send failed: {}", resp.text)
        except Exception as e:
            logger.error("DingTalk Card fallback send error: {}", e)

    # ── inbound ──────────────────────────────────────────────────────────

    async def _on_message(
        self,
        content: str,
        sender_id: str,
        sender_name: str,
        conversation_id: str,
        conversation_type: str,
    ) -> None:
        """Handle an incoming DingTalk message.

        Creates an AI Card *before* forwarding to the agent, so the card
        has time to register on the DingTalk side while the LLM processes
        the request.
        """
        # Cache conversation metadata for card creation
        self._conv_meta[sender_id] = {
            "conversation_id": conversation_id,
            "conversation_type": conversation_type,
            "sender_id": sender_id,
        }

        # Pre-create AI card — the LLM processing delay gives DingTalk
        # enough time to register the card before we stream content.
        if self.config.card_template_id:
            existing = self._active_cards.get(sender_id)
            if existing is None or existing.finished:
                await self._create_card(sender_id)

        await self._handle_message(
            sender_id=sender_id,
            chat_id=sender_id,
            content=content,
            metadata={
                "sender_name": sender_name,
                "platform": "dingtalk_card",
                "conversation_id": conversation_id,
                "conversation_type": conversation_type,
            },
        )
