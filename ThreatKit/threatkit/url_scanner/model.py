from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import os

# Absolute or relative local path to your downloaded model
MODEL_PATH = r"C:\Users\bbrad\ollama\urlbert"  # adjust if your model is elsewhere

# Confirm directory exists before loading
if not os.path.isdir(MODEL_PATH):
    raise FileNotFoundError(f"Model directory not found: {MODEL_PATH}")

# Load tokenizer and model from local directory
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)

def classify_url(url: str):
    """Classify a URL and return label + confidence."""
    inputs = tokenizer(url, return_tensors="pt", truncation=True)
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        label_id = torch.argmax(probs, dim=-1).item()
        label = model.config.id2label[label_id]
        confidence = probs[0][label_id].item()
    return {"label": label, "confidence": confidence}
