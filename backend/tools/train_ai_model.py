"""Train and persist the simple ML payload classifier for AI detection.

This script trains the `MLPayloadClassifier` using the built-in dataset
and saves the model artifact to `settings.AI_MODEL_PATH`.
"""
import os
from app.ai_detection import MLPayloadClassifier
from app.config import settings


def main():
    model_dir = os.path.dirname(settings.AI_MODEL_PATH)
    if model_dir and not os.path.exists(model_dir):
        os.makedirs(model_dir, exist_ok=True)

    clf = MLPayloadClassifier()
    queries, labels = clf.prepare_dataset()
    clf.train(queries, labels)
    clf.save_model(settings.AI_MODEL_PATH)
    print(f"Model trained and saved to {settings.AI_MODEL_PATH}")


if __name__ == '__main__':
    main()
