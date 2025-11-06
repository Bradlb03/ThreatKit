# threatkit/url_scanner/model_wrapper.py
from typing import Dict, Any
import threading

_tokenizer = None
_model = None
_model_lock = threading.Lock()
_LABELS = None  # ordered list of label names

# Fallback label names for URL classification models
_CARD_LABELS = [
    "legitimate_url",
    "phishing_url"
]

def _ensure_model_loaded():
    """Lazy-load the small URL classification model."""
    global _tokenizer, _model, _LABELS
    if _model is None or _tokenizer is None or _LABELS is None:
        with _model_lock:
            if _model is None or _tokenizer is None or _LABELS is None:
                try:
                    from transformers import AutoTokenizer, AutoModelForSequenceClassification
                    import torch  # noqa: F401
                except Exception as e:
                    raise RuntimeError("Install dependencies: pip install transformers torch") from e

                # Replace with your preferred local or Hugging Face model
                model_id = "DiligentAI/urlbert-url-classifier_v1.0.0"
                _tokenizer = AutoTokenizer.from_pretrained(model_id)
                _model = AutoModelForSequenceClassification.from_pretrained(model_id)
                _model.eval()

                # Resolve labels
                id2label = getattr(_model.config, "id2label", {}) or {}
                try:
                    labels = [id2label[str(i)] for i in range(_model.config.num_labels)]
                except Exception:
                    labels = []

                if not labels or all(l.startswith("LABEL_") for l in labels):
                    _LABELS = list(_CARD_LABELS)
                else:
                    _LABELS = labels


def predict_url(url: str) -> Dict[str, Any]:
    """Return a prediction + probabilities for a URL."""
    _ensure_model_loaded()
    import torch
    inputs = _tokenizer(url, return_tensors="pt", truncation=True, max_length=256)
    with torch.no_grad():
        outputs = _model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()

    labels_probs = {lbl: float(probs[i]) for i, lbl in enumerate(_LABELS)}
    pred_label, pred_conf = max(labels_probs.items(), key=lambda x: x[1])

    return {
        "prediction": pred_label,
        "confidence": pred_conf,
        "all_probabilities": labels_probs
    }