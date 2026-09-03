import os
import time

from dotenv import load_dotenv
from google import genai


# =========================================================
# ENVIRONMENT
# =========================================================

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError(
        "GEMINI_API_KEY not found. Please check your .env file."
    )


# =========================================================
# GEMINI CLIENT
# =========================================================

client = genai.Client(
    api_key=API_KEY
)


# Use a lightweight stable model suitable for
# repeated cybersecurity analysis requests.
MODEL_NAME = "gemini-3.5-flash-lite"


# =========================================================
# GEMINI ANALYSIS
# =========================================================

def generate_analysis(prompt):
    """
    Send a prompt to Gemini and return the generated text.

    Handles temporary 429 rate-limit errors with retries.
    """

    max_retries = 2

    for attempt in range(max_retries + 1):

        try:

            print(
                f"[GEMINI] Sending analysis request "
                f"(attempt {attempt + 1}/{max_retries + 1})..."
            )

            interaction = client.interactions.create(
                model=MODEL_NAME,
                input=prompt
            )

            print("[GEMINI] Analysis generated successfully.")

            return interaction.output_text


        except Exception as exc:

            error_text = str(exc)

            print(
                f"[GEMINI ERROR] {error_text}"
            )

            # -------------------------------------------------
            # Rate limit handling
            # -------------------------------------------------

            if (
                "429" in error_text
                or "RateLimitError" in error_text
                or "too_many_requests" in error_text
                or "RESOURCE_EXHAUSTED" in error_text
            ):

                if attempt < max_retries:

                    wait_time = 6 * (attempt + 1)

                    print(
                        f"[GEMINI] Rate limit reached. "
                        f"Retrying in {wait_time} seconds..."
                    )

                    time.sleep(wait_time)

                    continue

                print(
                    "[GEMINI] Rate limit still active "
                    "after retries."
                )

                raise

            # -------------------------------------------------
            # Other errors
            # -------------------------------------------------

            raise


# =========================================================
# DIRECT TEST
# =========================================================

if __name__ == "__main__":

    test_prompt = """
You are a cybersecurity analyst.

Explain BOLA (Broken Object Level Authorization)
in simple terms.

Also provide:

1. Why it is dangerous
2. One detection indicator
3. One recommended mitigation
"""

    result = generate_analysis(
        test_prompt
    )

    print(
        "\n===== GEMINI RESPONSE =====\n"
    )

    print(result)