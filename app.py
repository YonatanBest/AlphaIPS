from flask import Flask, render_template, redirect, url_for
import pandas as pd

app = Flask(__name__)

# Load the CSV file
def load_data():
    try:
        return pd.read_csv("network_traffic_predicted.csv")
    except FileNotFoundError:
        return pd.DataFrame(columns=["duration", "protocol_type", "service", "flag", 
                                      "src_bytes", "dst_bytes", "land", 
                                      "count", "srv_count", "result"])

@app.route('/')
def index():
    df = load_data()
    # Get the recent five predictions
    recent_predictions = df.tail(5).to_dict(orient='records')
    return render_template('index.html', predictions=recent_predictions)

@app.route('/history')
def history():
    df = load_data()
    all_predictions = df.to_dict(orient='records')
    return render_template('history.html', predictions=all_predictions)

if __name__ == '__main__':
    app.run(debug=True)
