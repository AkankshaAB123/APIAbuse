from pathlib import Path
import json

import numpy as np
from sentence_transformers import SentenceTransformer


# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent

EMBEDDINGS_FILE = (
    BASE_DIR
    / "embeddings"
    / "data"
    / "embeddings.npy"
)

METADATA_FILE = (
    BASE_DIR
    / "embeddings"
    / "data"
    / "metadata.json"
)


# Same model used during embedding generation
MODEL_NAME = "all-MiniLM-L6-v2"


def load_data():
    embeddings = np.load(EMBEDDINGS_FILE)

    with open(METADATA_FILE, "r", encoding="utf-8") as file:
        metadata = json.load(file)

    return embeddings, metadata


def search(query, top_k=3):
    """
    Find the most relevant security knowledge
    for a given threat/query.
    """

    embeddings, metadata = load_data()

    model = SentenceTransformer(MODEL_NAME)

    # Convert query into an embedding
    query_embedding = model.encode(
        query,
        convert_to_numpy=True,
        normalize_embeddings=True
    )

    # Cosine similarity because embeddings are normalized
    similarities = np.dot(
        embeddings,
        query_embedding
    )

    # Get highest scoring results
    top_indices = np.argsort(similarities)[::-1][:top_k]

    results = []

    for index in top_indices:
        results.append(
            {
                "filename": metadata[index]["filename"],
                "score": float(similarities[index]),
                "text": metadata[index]["text"],
            }
        )

    return results


if __name__ == "__main__":

    query = (
        "A user is accessing another user's resource "
        "by changing the object ID in an API request."
    )

    results = search(query, top_k=3)

    print("\n===== RETRIEVAL RESULTS =====\n")

    for result in results:
        print(
            f"File: {result['filename']}"
        )

        print(
            f"Similarity Score: "
            f"{result['score']:.4f}"
        )

        print()

        print(
            result["text"][:500]
        )

        print("\n" + "-" * 60)