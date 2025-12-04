# threatkit/emailcheck/model_wrapper.py
from typing import Dict, Any
import threading

_tokenizer = None
_model = None
_model_lock = threading.Lock()
_LABELS = None  # ordered list of label names

# Fallback label names (from the model card)
_CARD_LABELS = [
    "legitimate_email",  # index 0
    "phishing_url",      # index 1
    "legitimate_url",    # index 2
    "phishing_url_alt"   # index 3
]

def _ensure_model_loaded():
    global _tokenizer, _model, _LABELS
    if _model is None or _tokenizer is None or _LABELS is None:
        with _model_lock:
            if _model is None or _tokenizer is None or _LABELS is None:
                try:
                    from transformers import AutoTokenizer, AutoModelForSequenceClassification
                    import torch  # noqa: F401
                except Exception as e:
                    raise RuntimeError("Install dependencies: pip install transformers torch") from e

                model_id = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
                _tokenizer = AutoTokenizer.from_pretrained(model_id)
                _model = AutoModelForSequenceClassification.from_pretrained(model_id)
                _model.eval()

                id2label = getattr(_model.config, "id2label", {}) or {}
                try:
                    labels = [id2label[str(i)] for i in range(_model.config.num_labels)]
                except Exception:
                    labels = []

                if not labels or all(l.startswith("LABEL_") for l in labels):
                    _LABELS = list(_CARD_LABELS)
                else:
                    _LABELS = labels

def predict_email_text(email_text: str) -> Dict[str, Any]:
    _ensure_model_loaded()
    import torch
    inputs = _tokenizer(email_text, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = _model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0].tolist()

    labels_probs = {lbl: float(probs[i]) for i, lbl in enumerate(_LABELS)}
    pred_label, pred_conf = max(labels_probs.items(), key=lambda x: x[1])

    return {
        "prediction": pred_label,
        "confidence": pred_conf,          # top-class confidence (display only)
        "all_probabilities": labels_probs # used by detector to compute phishing prob
    }