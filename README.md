# momo

A scam alert detector. Analyzes messages (SMS, email, chat) for common
scam and phishing indicators such as urgency language, requests for
personal/financial info, prize claims, and suspicious links.

## Getting Started

Requires Python 3.8+.

Analyze a message directly:

```sh
python scam_detector.py "Congratulations! You've won a free gift. Click here to claim it!"
```

Or pipe text in via stdin:

```sh
echo "Your account has been suspended, verify now: bit.ly/abc123" | python scam_detector.py
```

### Running tests

```sh
pip install pytest
pytest
```

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

This project does not yet have a license specified.
