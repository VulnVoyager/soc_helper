import hashlib
import os
import tempfile
from aiogram import Router
from aiogram.types import Message, Document
from aiogram.filters import Command
from config import ALLOWED_USER_IDS
from utils.validators import is_ip, is_domain, is_hash, is_url
from utils.risk_assessment import assess_risk
from integrations import get_integrations
from aiocache import cached, Cache

router = Router()

async def check_access(message: Message) -> bool:
    if ALLOWED_USER_IDS and message.from_user.id not in ALLOWED_USER_IDS:
        await message.answer("🔒 Доступ запрещён.")
        return False
    return True

def detect_type(text: str) -> str | None:
    text = text.strip()
    if is_ip(text):
        return "ip"
    elif is_domain(text):
        return "domain"
    elif is_hash(text):
        return "hash"
    elif is_url(text):
        return "url"
    return None

@cached(ttl=3600, cache=Cache.MEMORY)
async def get_cached_report(indicator: str, indicator_type: str) -> str:
    integrations = get_integrations()
    raw_results = []
    formatted_results = []

    for integ in integrations:
        try:
            data = await integ.analyze(indicator, indicator_type)
            if data is not None:
                raw_results.append({"source": integ.name, "data": data})
                formatted_results.append(integ.format_result(data))
        except Exception as e:
            error_msg = f"❌ *{integ.name}*: ошибка"
            formatted_results.append(error_msg)

    risk_level = assess_risk(indicator_type, raw_results)

    if formatted_results:
        response = f"📊 Риск: *{risk_level}*\n\n" + "\n\n".join(formatted_results)
        if len(response) > 4000:
            response = response[:4000] + "…"
        return response
    else:
        return "📭 Нет данных от интеграций."

async def handle_ioc(message: Message, text: str):
    ioc_type = detect_type(text)
    if not ioc_type:
        await message.answer("⚠️ Не удалось распознать индикатор. Поддерживаются: IP, домен, хеш (MD5/SHA1/SHA256), URL.")
        return

    integrations = get_integrations()
    active_names = [integ.name for integ in integrations]
    await message.answer(
        f"🔍 Анализирую *{text}* как *{ioc_type}*...\n"
        f"Источники: {', '.join(active_names)}",
        parse_mode="Markdown"
    )

    response = await get_cached_report(text, ioc_type)
    await message.answer(response, parse_mode="Markdown", disable_web_page_preview=True)

async def handle_file(message: Message):
    doc: Document = message.document
    file_name = doc.file_name or "unknown"
    file_size = doc.file_size or 0

    if file_size > 30 * 1024 * 1024:
        await message.answer("❌ Файл слишком большой (лимит Telegram: 30 МБ).")
        return

    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_path = tmp_file.name

    try:
        bot = message.bot
        file = await bot.get_file(doc.file_id)
        await bot.download_file(file.file_path, tmp_path)

        sha256_hash = hashlib.sha256()
        with open(tmp_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        file_hash = sha256_hash.hexdigest()

        await message.answer(
            f"📎 Анализирую файл *{file_name}* по хешу:\n`{file_hash}`",
            parse_mode="Markdown"
        )

        response = await get_cached_report(file_hash, "hash")
        await message.answer(response, parse_mode="Markdown", disable_web_page_preview=True)

    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@router.message(Command("start"))
async def cmd_start(message: Message):
    await message.answer("👋 Отправь IP, домен, хеш, URL или файл для анализа.")

@router.message(Command("flush"))
async def cmd_flush(message: Message):
    if not await check_access(message):
        return
    cache = Cache()
    await cache.clear()
    await message.answer("🧹 Кэш успешно очищен. Следующие запросы будут обработаны заново.")

@router.message()
async def handle_message(message: Message):
    if not await check_access(message):
        return

    if message.document:
        await handle_file(message)
        return

    if message.text:
        if message.text.startswith("/"):
            return
        await handle_ioc(message, message.text)
