from pathlib import Path
import json

import numpy as np
from sentence_transformers import SentenceTransformer


# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
KNOWLEDGE_BASE_DIR = BASE_DIR / "knowledge_base"
OUTPUT_DIR = Path(__file__).resolve().parent / "data"

EMBEDDINGS_FILE = OUTPUT_DIR / "embeddings.npy"
METADATA_FILE = OUTPUT_DIR / "metadata.json"


# Embedding model
MODEL_NAME = "all-MiniLM-L6-v2"


def load_documents():
    documents = []

    for file_path in sorted(KNOWLEDGE_BASE_DIR.glob("*.md")):
        text = file_path.read_text(encoding="utf-8").strip()

        if not text:
            continue

        documents.append(
            {
                "filename": file_path.name,
                "text": text,
            }
        )

    return documents


def main():
    print("Loading knowledge base...")

    documents = load_documents()

    if not documents:
        print("No knowledge-base documents found.")
        return

    print(f"Found {len(documents)} documents.")

    print(f"Loading embedding model: {MODEL_NAME}")

    model = SentenceTransformer(MODEL_NAME)

    texts = [document["text"] for document in documents]

    print("Generating embeddings...")

    embeddings = model.encode(
        texts,
        convert_to_numpy=True,
        normalize_embeddings=True
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    np.save(EMBEDDINGS_FILE, embeddings)

    metadata = [
        {
            "filename": document["filename"],
            "text": document["text"],
        }
        for document in documents
    ]

    with open(METADATA_FILE, "w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2, ensure_ascii=False)

    print()
    print("Embedding generation completed.")
    print(f"Embeddings saved to: {EMBEDDINGS_FILE}")
    print(f"Metadata saved to: {METADATA_FILE}")
    print(f"Embedding shape: {embeddings.shape}")


if __name__ == "__main__":
    main()