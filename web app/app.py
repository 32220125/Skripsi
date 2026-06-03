from flask import Flask, render_template, request
from Skripsi import URLAnalyzer  #analyzer file

app = Flask(__name__)


def get_risk_status(score):
    """
    Convert numeric score into descriptive risk level
    """

    if score <= 20:
        return {
            "label": "SANGAT AMAN",
            "description": "URL terlihat normal dan hampir tidak memiliki indikator mencurigakan."
        }

    elif score <= 40:
        return {
            "label": "AMAN",
            "description": "Terdapat sedikit indikator mencurigakan, tetapi link masih relatif aman."
        }

    elif score <= 60:
        return {
            "label": "WASPADA",
            "description": "Link memiliki beberapa pola yang sering ditemukan pada phishing atau spam."
        }

    elif score <= 70:
        return {
            "label": "CUKUP BERISIKO",
            "description": "URL memiliki banyak indikator mencurigakan. Hindari memasukkan data pribadi atau password."
        }

    elif score <= 90:
        return {
            "label": "BERBAHAYA",
            "description": "Kemungkinan phishing atau malware cukup tinggi. Disarankan untuk tidak membuka link."
        }

    else:
        return {
            "label": "SANGAT BERBAHAYA",
            "description": "URL sangat berpotensi mengandung phishing, malware, scam, atau pencurian data."
        }


@app.route("/", methods=["GET", "POST"])
def index():

    result = None
    score = None
    status = None
    description = None
    url_input = None

    if request.method == "POST":

        url_input = request.form["url"]

        try:
            # Create analyzer
            analyzer = URLAnalyzer()

            # Analyze URL
            result = analyzer.analyze(url_input)

            # Get risk score
            score = analyzer.get_risk_score()

            # Get descriptive status
            risk_info = get_risk_status(score)

            status = risk_info["label"]
            description = risk_info["description"]

            # Console output
            print(f"Analyzing URL: {url_input}")
            print(f"Risk Score: {score}")
            print(f"Status: {status}")

        except Exception as e:

            result = {
                "error": str(e)
            }

            print(f"ERROR: {e}")

    return render_template(
        "index.html",
        result=result,
        score=score,
        status=status,
        description=description,
        url_input=url_input
    )


if __name__ == "__main__":
    app.run(debug=True)
