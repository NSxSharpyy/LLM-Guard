from presidio_analyzer import AnalyzerEngine


def main():
    print("[*] Initializing Presidio Analyzer...")

    analyzer = AnalyzerEngine()

    sample_text = (
        "My name is John Smith and my email is "
        "john.smith@example.com"
    )

    print("[*] Analyzing sample text...")

    results = analyzer.analyze(
        text=sample_text,
        language="en"
    )

    detected_entities = [result.entity_type for result in results]

    print("\nDetected entities:")

    for result in results:
        print(
            f"Entity: {result.entity_type} | "
            f"Text: {sample_text[result.start:result.end]} | "
            f"Score: {result.score:.2f}"
        )

    assert "EMAIL_ADDRESS" in detected_entities, (
        "Email detection failed!"
    )

    assert "PERSON" in detected_entities, (
        "Person detection failed!"
    )

    print("\n[+] Email detection successful!")
    print("[+] Person detection successful!")
    print("[+] Presidio setup verification PASSED!")


if __name__ == "__main__":
    main()
