from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_PATH = "/home/bradlb03/ollama/urlbert"

tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

def classify_url(url: str):
    """Classify a URL using the local Hugging Face model."""
    inputs = tokenizer(url, return_tensors="pt", truncation=True, max_length=64)
    with torch.no_grad():
        outputs = model(**inputs)
        scores = torch.nn.functional.softmax(outputs.logits, dim=-1)
        label_idx = torch.argmax(scores, dim=-1).item()
        confidence = scores[0][label_idx].item()

    label_map = {0: "official_website", 1: "platform"}
    return {"label": label_map[label_idx], "confidence": round(confidence, 3)}