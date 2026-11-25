"""Offline AI Threat Hunt Assistant for Fintech Mini-SIEM.

Supports English and Russian natural language queries with intent parsing
for common security investigation patterns.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class HuntIntent:
    """Parsed intent from natural language query."""
    intent_type: str  # brute_force, impossible_travel, non_compliant_devices, payment_fraud, executive_brief
    params: dict
    spl_query: str
    summary_en: str
    summary_ru: str
    recommended_actions: list[dict]  # SOAR buttons


class OfflineIntentParser:
    """Offline intent parser for threat hunting queries in English and Russian."""

    # Intent patterns for English
    EN_PATTERNS = {
        'brute_force': [
            r'(?i)(brute.?force|bruteforce|password.?guess|credential.?stuff|login.?fail|failed.?login).*?(ip|address|source)?',
            r'(?i)(who|which).*?(attack|attacker|brute).*(ip|address|source)',
            r'(?i)(show|find|list).*?(failed|unsuccessful).*?login',
        ],
        'impossible_travel': [
            r'(?i)(impossible.?travel|travel.?anomal|geo.?impossible|location.?anomal|simultaneous.?login|multiple.?countries|different.?countries)',
            r'(?i)(user|account).*?(login|access).*?(different|multiple).*?countr',
            r'(?i)(impossible|improbable).*?(distance|travel|location)',
        ],
        'non_compliant_devices': [
            r'(?i)(non.?compliant|noncompliant|not.?compliant|compliance.?fail|device.?compliance|outdated|unpatched|vulnerable.*device)',
            r'(?i)(which|what|show|list|find).*?device.*?(non.?compliant|not.?compliant|exception|risk)',
            r'(?i)(compliance.?status|device.?posture|fleet.?health)',
        ],
        'payment_fraud': [
            r'(?i)(payment.?fraud|wire.?fraud|high.?value.?transfer|large.?transfer|suspicious.?transaction|fraudulent.?payment|money.?launder)',
            r'(?i)(unusual|suspicious|anomalous).*?(payment|transfer|transaction|wire)',
            r'(?i)(high.?value|large|big).*?(payment|transfer|wire|transaction)',
        ],
        'executive_brief': [
            r'(?i)(executive.?brief|summary|overview|dashboard|status.?report|daily.?report|threat.?landscape|security.?posture)',
            r'(?i)(what.*?happen|current.?state|overall.?status|high.?level)',
        ],
    }

    # Intent patterns for Russian
    RU_PATTERNS = {
        'brute_force': [
            r'(?i)(брут.?форс|подбор.?парол|брутфорс|неудачн.?логин|неудачн.?вход|атака.?парол|credential.?stuffing)',
            r'(?i)(кто|какой).*(атак|брут).*(ip|адрес|источник)',
            r'(?i)(покажи|найди|список).*(неудачн|ошибк).*?(логин|вход)',
        ],
        'impossible_travel': [
            r'(?i)(невозможн.?путешеств|невозможн.?тревел|гео.?аномал|одновременн.?вход|разн.?стран|двух.?стран)',
            r'(?i)(пользователь|аккаунт).*(вход|логин).*(разн|множеств).*?стра',
            r'(?i)(невозможн|нереальн).*(рассто|путешеств|локац)',
        ],
        'non_compliant_devices': [
            r'(?i)(не.?соответств|несоответств|не.?комплаенс|устаревш|непатчен|уязвим.?устройств|комплаенс.?устройств)',
            r'(?i)(какие|какой|покажи|найди|список).*(устройств|девайс).*(не.?соответств|риск|исключен)',
            r'(?i)(статус.?комплаенс|состояние.?парк|здоровье.?флот)',
        ],
        'payment_fraud': [
            r'(?i)(платежн.?мошен|wire.?fraud|крупн.?перевод|подозрительн.?транзакц|мошенническ.?платеж|отмыван)',
            r'(?i)(необычн|подозрительн|аномальн).*(плат|перевод|транзакц|wire)',
            r'(?i)(крупн|больш|высок).*(плат|перевод|wire|транзакц)',
        ],
        'executive_brief': [
            r'(?i)(исполнит.?кратк|кратк.?отчет|обзор|дашборд|статус.?отчет|ежедневн.?отчет|ландшафт.?угроз|безопасн.?поза)',
            r'(?i)(что.*?происход|текущ.?состояние|общ.?статус|высок.?уровн)',
        ],
    }

    # SPL query templates
    SPL_TEMPLATES = {
        'brute_force': (
            "source_type=auth status=failed "
            "| stats count by source_ip, user_id "
            "| where count > 5 "
            "| sort -count"
        ),
        'impossible_travel': (
            "source_type=auth status=success "
            "| stats count, min(_time) as first_login, max(_time) as last_login by user_id, country "
            "| where country_count > 1 "
            "| eval time_diff = last_login - first_login "
            "| where time_diff < 3600"
        ),
        'non_compliant_devices': (
            "source_type=compliance compliance_status!=Compliant "
            "| stats count by device_id, hostname, compliance_status, edr_status "
            "| sort -count"
        ),
        'payment_fraud': (
            "source_type=payment amount>10000 "
            "| stats count, sum(amount) as total_amount by user_id, recipient, source_ip "
            "| where count > 1 OR total_amount > 50000 "
            "| sort -total_amount"
        ),
        'executive_brief': (
            "* "
            "| stats count by source_type, severity "
            "| eval risk_level = case(severity==\"CRITICAL\", 4, severity==\"HIGH\", 3, severity==\"MEDIUM\", 2, 1=1, 1)"
        ),
    }

    # Summaries in English
    SUMMARIES_EN = {
        'brute_force': "Detected brute-force login attempts: multiple failed authentications from same source IP targeting user accounts.",
        'impossible_travel': "Identified impossible travel anomalies: successful logins for same user from geographically distant locations within implausible timeframes.",
        'non_compliant_devices': "Found non-compliant devices in fleet: devices with outdated agents, missing patches, or policy violations.",
        'payment_fraud': "Detected suspicious high-value payment patterns: unusual wire transfers, large transactions to new recipients, or velocity anomalies.",
        'executive_brief': "Executive security posture summary: overall threat landscape, critical alerts, fleet compliance, and key risk indicators.",
    }

    # Summaries in Russian
    SUMMARIES_RU = {
        'brute_force': "Обнаружены атаки перебором паролей: множественные неудачные аутентификации с одного IP-адреса на учетные записи пользователей.",
        'impossible_travel': "Выявлены аномалии невозможных перемещений: успешные входы одного пользователя из географически удаленных локаций в нереалистичные временные рамки.",
        'non_compliant_devices': "Найдены несоответствующие устройства в парке: устройства с устаревшими агентами, отсутствующими патчами или нарушениями политики.",
        'payment_fraud': "Обнаружены подозрительные схемы крупных платежей: необычные банковские переводы, крупные транзакции новым получателям или аномалии скорости.",
        'executive_brief': "Краткий отчет для руководства: общий ландшафт угроз, критические алерты, соответствие парка и ключевые индикаторы риска.",
    }

    # Recommended SOAR actions per intent
    RECOMMENDED_ACTIONS = {
        'brute_force': [
            {'label': 'Block Attacker IP', 'action': 'block_ip', 'target_param': 'source_ip', 'style': 'danger'},
            {'label': 'Freeze Targeted Accounts', 'action': 'freeze_account', 'target_param': 'user_id', 'style': 'warning'},
            {'label': 'View Full Alert Details', 'action': 'view_alerts', 'target_param': None, 'style': 'secondary'},
        ],
        'impossible_travel': [
            {'label': 'Freeze Compromised Account', 'action': 'freeze_account', 'target_param': 'user_id', 'style': 'danger'},
            {'label': 'Revoke All Sessions', 'action': 'revoke_sessions', 'target_param': 'user_id', 'style': 'warning'},
            {'label': 'Block Suspicious IPs', 'action': 'block_ip', 'target_param': 'source_ip', 'style': 'warning'},
            {'label': 'View Full Alert Details', 'action': 'view_alerts', 'target_param': None, 'style': 'secondary'},
        ],
        'non_compliant_devices': [
            {'label': 'Isolate Non-Compliant Device', 'action': 'isolate_device', 'target_param': 'device_id', 'style': 'danger'},
            {'label': 'View Device Details', 'action': 'view_device', 'target_param': 'device_id', 'style': 'secondary'},
            {'label': 'Generate Compliance Report', 'action': 'compliance_report', 'target_param': None, 'style': 'primary'},
        ],
        'payment_fraud': [
            {'label': 'Freeze User Account', 'action': 'freeze_account', 'target_param': 'user_id', 'style': 'danger'},
            {'label': 'Block Source IP', 'action': 'block_ip', 'target_param': 'source_ip', 'style': 'danger'},
            {'label': 'Revoke Sessions', 'action': 'revoke_sessions', 'target_param': 'user_id', 'style': 'warning'},
            {'label': 'View Transaction Details', 'action': 'view_transactions', 'target_param': None, 'style': 'secondary'},
        ],
        'executive_brief': [
            {'label': 'View Critical Alerts', 'action': 'view_critical_alerts', 'target_param': None, 'style': 'danger'},
            {'label': 'View Fleet Posture', 'action': 'view_fleet', 'target_param': None, 'style': 'primary'},
            {'label': 'Generate Full Report', 'action': 'full_report', 'target_param': None, 'style': 'secondary'},
        ],
    }

    def __init__(self):
        self.compiled_en = {k: [re.compile(p) for p in v] for k, v in self.EN_PATTERNS.items()}
        self.compiled_ru = {k: [re.compile(p) for p in v] for k, v in self.RU_PATTERNS.items()}

    def parse(self, prompt: str, lang: str = 'en') -> HuntIntent:
        """Parse natural language prompt into structured intent."""
        prompt_lower = prompt.lower()

        # Select pattern set based on language
        patterns = self.compiled_ru if lang == 'ru' else self.compiled_en

        # Match intent
        detected_intent = None
        max_matches = 0

        for intent_type, compiled_patterns in patterns.items():
            matches = sum(1 for p in compiled_patterns if p.search(prompt_lower))
            if matches > max_matches:
                max_matches = matches
                detected_intent = intent_type

        # Default to executive_brief if no match
        if not detected_intent:
            detected_intent = 'executive_brief'

        # Extract parameters based on intent
        params = self._extract_params(prompt, detected_intent)

        # Get SPL query
        spl_query = self.SPL_TEMPLATES.get(detected_intent, self.SPL_TEMPLATES['executive_brief'])

        # Get summaries
        summary_en = self.SUMMARIES_EN.get(detected_intent, self.SUMMARIES_EN['executive_brief'])
        summary_ru = self.SUMMARIES_RU.get(detected_intent, self.SUMMARIES_RU['executive_brief'])

        # Get recommended actions
        recommended_actions = self.RECOMMENDED_ACTIONS.get(detected_intent, self.RECOMMENDED_ACTIONS['executive_brief'])

        return HuntIntent(
            intent_type=detected_intent,
            params=params,
            spl_query=spl_query,
            summary_en=summary_en,
            summary_ru=summary_ru,
            recommended_actions=recommended_actions
        )

    def _extract_params(self, prompt: str, intent_type: str) -> dict:
        """Extract parameters from prompt based on intent type."""
        params = {}

        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, prompt)
        if ips:
            params['source_ip'] = ips[0]
            params['ips'] = ips

        # Extract user IDs (EMP-XXX format)
        user_pattern = r'\b(EMP-\d{3})\b'
        users = re.findall(user_pattern, prompt, re.IGNORECASE)
        if users:
            params['user_id'] = users[0]
            params['user_ids'] = users

        # Extract device IDs (DEV-XXXX format)
        device_pattern = r'\b(DEV-\d{4})\b'
        devices = re.findall(device_pattern, prompt, re.IGNORECASE)
        if devices:
            params['device_id'] = devices[0]
            params['device_ids'] = devices

        # Extract amounts
        amount_pattern = r'\$?(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)'
        amounts = re.findall(amount_pattern, prompt)
        if amounts:
            params['amounts'] = amounts

        # MITRE IDs
        mitre_pattern = r'\b(T\d{4}(?:\.\d{3})?)\b'
        mitre_ids = re.findall(mitre_pattern, prompt, re.IGNORECASE)
        if mitre_ids:
            params['mitre_ids'] = mitre_ids

        return params


# Global parser instance
_parser = OfflineIntentParser()


def parse_hunt_query(prompt: str, lang: str = 'en') -> HuntIntent:
    """Parse a natural language threat hunting query."""
    return _parser.parse(prompt, lang)


def get_spl_query(intent_type: str) -> str:
    """Get SPL query template for an intent type."""
    return _parser.SPL_TEMPLATES.get(intent_type, _parser.SPL_TEMPLATES['executive_brief'])


def get_summary(intent_type: str, lang: str = 'en') -> str:
    """Get summary for an intent type in specified language."""
    if lang == 'ru':
        return _parser.SUMMARIES_RU.get(intent_type, _parser.SUMMARIES_RU['executive_brief'])
    return _parser.SUMMARIES_EN.get(intent_type, _parser.SUMMARIES_EN['executive_brief'])


def get_recommended_actions(intent_type: str) -> list[dict]:
    """Get recommended SOAR actions for an intent type."""
    return _parser.RECOMMENDED_ACTIONS.get(intent_type, _parser.RECOMMENDED_ACTIONS['executive_brief'])