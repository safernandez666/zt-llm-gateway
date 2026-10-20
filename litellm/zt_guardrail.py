"""
Guardrail de LiteLLM: la capa que no se puede saltear.

El orquestador también llama al servicio de guardrails — pero el orquestador
es código de aplicación, y el código de aplicación se saltea. Alguien con una
virtual key le pega directo al puerto 4000 y listo.

Este hook corre en el gateway, del lado de adentro del único componente que
tiene las credenciales de los modelos. Si no pasa por acá, no hay inferencia.

  pre_call   -> ¿este prompt entra al modelo?
  post_call  -> ¿qué hay que tapar antes de devolverlo?
"""
import os
from typing import Any, Literal, Optional, Union

import httpx
from fastapi import HTTPException
from litellm.caching.caching import DualCache
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm.proxy._types import UserAPIKeyAuth

GUARDRAILS_URL = os.getenv("GUARDRAILS_URL", "http://guardrails:8002")


def _texto_de_mensajes(data: dict) -> str:
    partes = []
    for m in data.get("messages", []):
        if m.get("role") == "system":
            continue  # el system prompt es nuestro, no hace falta escanearlo
        contenido = m.get("content")
        if isinstance(contenido, str):
            partes.append(contenido)
        elif isinstance(contenido, list):
            partes.extend(c.get("text", "") for c in contenido if isinstance(c, dict))
    return "\n".join(partes)


class ZeroTrustGuardrail(CustomGuardrail):
    async def async_pre_call_hook(
        self,
        user_api_key_dict: UserAPIKeyAuth,
        cache: DualCache,
        data: dict,
        call_type: str,
    ) -> Optional[Union[Exception, str, dict]]:
        texto = _texto_de_mensajes(data)
        if not texto.strip():
            return data

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.post(
                    f"{GUARDRAILS_URL}/scan/input",
                    json={"text": texto, "allow_entities": []},
                )
                veredicto = r.json()
        except Exception:
            # Fail-open en el gateway sería peor que no tener guardrail:
            # da la sensación de control sin el control.
            raise HTTPException(
                status_code=503,
                detail={"error": "guardrails no disponible: la llamada no se ejecuta"},
            )

        if not veredicto.get("allow", False):
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "bloqueado por el gateway",
                    "motivo": veredicto.get("reason", ""),
                    "guardrail": "zt-input",
                },
            )
        return data

    async def async_post_call_success_hook(
        self,
        data: dict,
        user_api_key_dict: UserAPIKeyAuth,
        response: Any,
    ) -> Any:
        try:
            choices = getattr(response, "choices", None) or []
            for choice in choices:
                mensaje = getattr(choice, "message", None)
                contenido = getattr(mensaje, "content", None) if mensaje else None
                if not contenido:
                    continue
                async with httpx.AsyncClient(timeout=20) as client:
                    r = await client.post(
                        f"{GUARDRAILS_URL}/scan/output",
                        json={"text": contenido, "allow_entities": []},
                    )
                    mensaje.content = r.json()["text"]
        except Exception:
            # Si el escaneo de salida falla, devolvemos la respuesta tapada
            # entera antes que arriesgar un PAN en claro.
            for choice in getattr(response, "choices", []) or []:
                mensaje = getattr(choice, "message", None)
                if mensaje and getattr(mensaje, "content", None):
                    mensaje.content = "[REDACTED: el guardrail de salida no pudo verificar esta respuesta]"
        return response
