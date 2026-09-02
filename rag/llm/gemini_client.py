import os

from dotenv import load_dotenv
from google import genai


# Load variables from .env
load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if not API_KEY:
    raise ValueError(
        "GEMINI_API_KEY not found. "
        "Please check your .env file."
    )


# Create Gemini client
client = genai.Client(api_key=API_KEY)

MODEL_NAME = "gemini-3.6-flash"


def generate_analysis(prompt):
    """
    Send a prompt to Gemini using the Interactions API
    and return the generated response.
    """

    interaction = client.interactions.create(
        model=MODEL_NAME,
        input=prompt
    )

    return interaction.output_text


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

    result = generate_analysis(test_prompt)

    print("\n===== GEMINI RESPONSE =====\n")
    print(result)