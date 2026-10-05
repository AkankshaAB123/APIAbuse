from pathlib import Path
import json

import numpy as np
from sentence_transformers import SentenceTransformer


# ============================================================
# PROJECT PATHS
# ============================================================

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


# ============================================================
# EMBEDDING MODEL
# ============================================================

MODEL_NAME = "all-MiniLM-L6-v2"


# Load the embedding model only ONCE.
# Previously, the model was loaded every time search()
# was called, which made API requests very slow.
print("[RAG] Loading embedding model...")

_model = SentenceTransformer(MODEL_NAME)

print("[RAG] Embedding model loaded successfully.")


# ============================================================
# LOAD KNOWLEDGE BASE DATA
# ============================================================

print("[RAG] Loading embeddings and metadata...")

_embeddings = np.load(EMBEDDINGS_FILE)

with open(METADATA_FILE, "r", encoding="utf-8") as file:
    _metadata = json.load(file)

print(
    f"[RAG] Loaded {_embeddings.shape[0]} knowledge documents."
)


# ============================================================
# SEARCH
# ============================================================

def search(query, top_k=3):
    """
    Find the most relevant security knowledge
    for a given threat/query.
    """

    print("[RAG] Creating query embedding...")

    query_embedding = _model.encode(
        query,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )

    print("[RAG] Calculating similarity scores...")

    # Because both the stored embeddings and query embedding
    # are normalized, dot product gives cosine similarity.
    similarities = np.dot(
        _embeddings,
        query_embedding,
    )

    # Get indices of the highest similarity scores.
    top_indices = np.argsort(similarities)[::-1][:top_k]

    results = []

    for index in top_indices:
        results.append(
            {
                "filename": _metadata[index]["filename"],
                "score": float(similarities[index]),
                "text": _metadata[index]["text"],
            }
        )

    print(f"[RAG] Retrieved top {len(results)} documents:")

    for result in results:
        print(
            f"[RAG] {result['filename']} "
            f"(score: {result['score']:.4f})"
        )

    return results


# ============================================================
# TEST RETRIEVAL
# ============================================================

if __name__ == "__main__":

    query = (
        "A user is accessing another user's resource "
        "by changing the object ID in an API request."
    )

    results = search(query, top_k=3)

    print("\n===== RETRIEVAL RESULTS =====\n")

    for result in results:

        print(f"File: {result['filename']}")

        print(
            f"Similarity Score: "
            f"{result['score']:.4f}"
        )

        print()

        print(
            result["text"][:500]
        )

        print("\n" + "-" * 60)