"""
title: LLM Guard Filter Pipeline
author: jannikstdl, ozeliurs
date: 2024-05-30, 2025-03-23
version: 1.0
license: MIT
description: A pipeline for filtering out potential prompt injections using the LLM Guard library.
requirements: llm-guard
"""

from typing import List, Optional

from llm_guard.input_scanners import BanSubstrings, PromptInjection  # ,Secrets
from llm_guard.input_scanners.ban_substrings import MatchType as bs_match_type
from llm_guard.input_scanners.prompt_injection import MatchType as pi_match_type
from pydantic import BaseModel

forbidden_strings = [
    "StartupNation Confidential",
]


class Pipeline:
    def __init__(self):
        # Pipeline filters are only compatible with Open WebUI
        # You can think of filter pipeline as a middleware that can be used to edit the form data before it is sent to the OpenAI API.
        self.type = "filter"

        # Optionally, you can set the id and name of the pipeline.
        # Assign a unique identifier to the pipeline.
        # The identifier must be unique across all pipelines.
        # The identifier must be an alphanumeric string that can include underscores or hyphens. It cannot contain spaces, special characters, slashes, or backslashes.
        self.id = "llmguard_prompt_injection_filter_pipeline"
        self.name = "LLMGuard Prompt Injection Filter"

        class Valves(BaseModel):
            # List target pipeline ids (models) that this filter will be connected to.
            # If you want to connect this filter to all pipelines, you can set pipelines to ["*"]
            # e.g. ["llama3:latest", "gpt-3.5-turbo"]
            pipelines: List[str] = []

            # Assign a priority level to the filter pipeline.
            # The priority level determines the order in which the filter pipelines are executed.
            # The lower the number, the higher the priority.
            priority: int = 0

        # Initialize
        self.valves = Valves(
            **{
                "pipelines": ["*"],  # Connect to all pipelines
            }
        )

        self.pi_model = None
        self.bs_model = None

        pass

    async def on_startup(self):
        # This function is called when the server is started.
        print(f"on_startup:{__name__}")

        self.pi_model = PromptInjection(threshold=0.8, match_type=pi_match_type.FULL)
        self.bs_model = BanSubstrings(
            substrings=forbidden_strings,
            match_type=bs_match_type.STR,
            case_sensitive=False,
            redact=False,
            contains_all=False,
        )

    async def on_shutdown(self):
        # This function is called when the server is stopped.
        print(f"on_shutdown:{__name__}")
        pass

    async def on_valves_updated(self):
        # This function is called when the valves are updated.
        pass

    async def inlet(self, body: dict, user: Optional[dict] = None) -> dict:
        print(f"inlet:{__name__}")

        user_message = body["messages"][-1]["content"]

        if body["metadata"]["files"] is None:
            body["metadata"]["files"] = []

        files_contents = [
            (
                file["file"]["data"]["content"]
                if (
                    "file" in file
                    and "data" in file["file"]
                    and "content" in file["file"]["data"]
                )
                else ""
            )
            for file in body["metadata"]["files"]
        ]

        # Filter out prompt injection messages
        sanitized_prompt, is_valid, risk_score = self.pi_model.scan(user_message)

        if risk_score > 0.8:
            raise Exception(
                "Prompt injection detected with risk score: {:.2f}".format(risk_score)
            )

        # Filter out confidential information
        full_content = user_message + " " + " ".join(files_contents)
        sanitized_prompt, is_valid, risk_score = self.bs_model.scan(full_content)

        if not is_valid:
            # Find which forbidden strings were matched
            matched_strings = []
            for forbidden in forbidden_strings:
                if forbidden.lower() in full_content.lower():
                    # Get some context around the match
                    index = full_content.lower().find(forbidden.lower())
                    start = max(0, index - 20)
                    end = min(len(full_content), index + len(forbidden) + 20)
                    context = full_content[start:end]
                    matched_strings.append(
                        {"forbidden_string": forbidden, "context": f"...{context}..."}
                    )

            error_message = "Confidential information detected:\n"
            for match in matched_strings:
                error_message += f"\n- Found '{match['forbidden_string']}' in context:\n  {match['context']}"

            raise Exception(error_message)

        return body
