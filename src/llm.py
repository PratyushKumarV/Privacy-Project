import json
import requests

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral:latest"


def generate(prompt, model=MODEL, json_mode=False, temperature=0.1):
    body = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": temperature},
    }
    if json_mode:
        body["format"] = "json"
    r = requests.post(OLLAMA_URL, json=body, timeout=300)
    r.raise_for_status()
    return r.json()["response"]


if __name__ == "__main__":
    print(generate("In one sentence, what is a TCP SYN flood?"))
    out = generate(
        'Reply only with JSON like {"attack": "<name>", "severity": "<low|medium|high>"} '
        "for a TCP SYN flood.",
        json_mode=True,
    )
    print(out)
    print(json.loads(out))