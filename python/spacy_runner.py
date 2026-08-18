#!/usr/bin/env python3
import json
import sys

def print_log_output(type: str, message: str, data):
    p = json.dumps({"type": type, "message": message, "data": data})
    print(p, flush=True)

try:
    print_log_output("log", "Importing required libraries", None)

    import en_core_web_lg
    print_log_output("log", "Successfully imported required libraries", None)

    nlp = en_core_web_lg.load()
    print_log_output("log", "Successfully loaded model", None)

    for i in sys.stdin:
        try:
            i = i.strip()
            doc = nlp(i)
            print_log_output("output", "Successfully processed text", {
                "text": i,
                "entities": [{"text": ent.text, "label": ent.label_} for ent in doc.ents]
            })
        except ImportError:
            print_log_output("error", "Failed to import required libraries", None)
        except Exception as e:
            print_log_output("error", str(e), None)

except ImportError:
    print_log_output("error", "Failed to import required libraries", None)
except Exception as e:
    print_log_output("error", str(e), None)
finally:
    print_log_output("exit", "Exiting", None)
