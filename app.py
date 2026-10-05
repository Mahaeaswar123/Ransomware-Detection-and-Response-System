from flask import Flask, render_template, jsonify, request
import psutil
import os

from database import (
    init_database,
    get_recent_events,
    get_recent_alerts
)

from detector import Monitor


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(__name__)

monitor = Monitor()


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

init_database()


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


# =========================================================
# SYSTEM STATUS
# =========================================================

@app.route("/api/status")
def status():

    try:

        data = monitor.get_status()

        return jsonify(data)

    except Exception as error:

        return jsonify({
            "monitoring": False,
            "folder": None,
            "risk": "LOW",
            "event_count": 0,
            "unique_file_count": 0,
            "change_count": 0,
            "suspicious_path": None,
            "suspicious_pid": None,
            "suspicious_process": None,
            "error": str(error)
        }), 500


# =========================================================
# START PROTECTION
# =========================================================

@app.route("/api/start", methods=["POST"])
def start_monitoring():

    try:

        data = request.get_json(silent=True) or {}

        folder_path = data.get("folder")

        if not folder_path:
            folder_path = os.path.expanduser("~")

        folder_path = os.path.abspath(folder_path)

        if not os.path.isdir(folder_path):

            return jsonify({
                "success": False,
                "message": f"Folder does not exist: {folder_path}"
            }), 400

        started = monitor.start(folder_path)

        if not started:

            return jsonify({
                "success": False,
                "message": "Monitoring is already running",
                "folder": monitor.folder
            })

        return jsonify({

            "success": True,

            "message":
                "Ransomware protection started successfully",

            "folder":
                monitor.folder,

            "risk":
                monitor.get_status()["risk"]
        })

    except Exception as error:

        return jsonify({

            "success": False,

            "message": str(error)

        }), 500


# =========================================================
# STOP PROTECTION
# =========================================================

@app.route("/api/stop", methods=["POST"])
def stop_monitoring():

    try:

        stopped = monitor.stop()

        if stopped:

            return jsonify({

                "success": True,

                "message":
                    "Ransomware protection stopped",

                "monitoring":
                    False
            })

        return jsonify({

            "success": False,

            "message":
                "Monitoring is not currently running",

            "monitoring":
                False
        })

    except Exception as error:

        return jsonify({

            "success": False,

            "message": str(error)

        }), 500


# =========================================================
# STOP SUSPICIOUS PROCESS
# =========================================================

@app.route("/api/stop-process", methods=["POST"])
def stop_process():

    # -----------------------------------------------------
    # Check monitoring
    # -----------------------------------------------------

    if not monitor.monitoring:

        return jsonify({

            "success": False,

            "message":
                "Monitoring is not running"

        }), 400


    # -----------------------------------------------------
    # Check detector
    # -----------------------------------------------------

    if not monitor.detector:

        return jsonify({

            "success": False,

            "message":
                "Detector is not available"

        }), 400


    # -----------------------------------------------------
    # Get suspicious PID
    # -----------------------------------------------------

    pid = monitor.detector.suspicious_pid

    if not pid:

        return jsonify({

            "success": False,

            "message":
                "No suspicious process identified"

        }), 400


    try:

        process = psutil.Process(pid)

        process_name = process.name()


        # -------------------------------------------------
        # Safety check
        # -------------------------------------------------

        protected_processes = {

            "system",
            "system idle process",
            "smss.exe",
            "csrss.exe",
            "wininit.exe",
            "winlogon.exe",
            "services.exe",
            "lsass.exe",
            "svchost.exe",
            "explorer.exe"

        }


        if process_name.lower() in protected_processes:

            return jsonify({

                "success": False,

                "message": (
                    f"Protected system process "
                    f"{process_name} cannot be stopped."
                ),

                "pid": pid,

                "process": process_name

            }), 403


        # -------------------------------------------------
        # Terminate suspicious process
        # -------------------------------------------------

        print(
            f"🛑 Stopping suspicious process: "
            f"{process_name} (PID: {pid})"
        )

        process.terminate()


        try:

            process.wait(timeout=3)

        except psutil.TimeoutExpired:

            return jsonify({

                "success": False,

                "message": (
                    f"Process {process_name} "
                    f"(PID {pid}) did not terminate."
                ),

                "pid": pid,

                "process": process_name

            }), 500


        # -------------------------------------------------
        # IMPORTANT:
        # Reset complete threat state
        # HIGH -> LOW
        # -------------------------------------------------

        monitor.detector.reset_threat()


        print(
            f"✅ Suspicious process stopped: "
            f"{process_name} (PID: {pid})"
        )

        print(
            "✅ Threat state reset. Risk = LOW"
        )


        return jsonify({

            "success": True,

            "message": (
                f"Suspicious process "
                f"{process_name} "
                f"(PID {pid}) was stopped."
            ),

            "pid": pid,

            "process": process_name,

            "risk": "LOW"

        })


    # -----------------------------------------------------
    # Process already stopped
    # -----------------------------------------------------

    except psutil.NoSuchProcess:

        monitor.detector.reset_threat()

        return jsonify({

            "success": True,

            "message": (
                f"Process PID {pid} "
                f"is no longer running."
            ),

            "pid": pid,

            "risk": "LOW"

        })


    # -----------------------------------------------------
    # Permission error
    # -----------------------------------------------------

    except psutil.AccessDenied:

        return jsonify({

            "success": False,

            "message": (
                "Permission denied while stopping "
                "the suspicious process."
            ),

            "pid": pid

        }), 403


    # -----------------------------------------------------
    # Other errors
    # -----------------------------------------------------

    except Exception as error:

        return jsonify({

            "success": False,

            "message": str(error),

            "pid": pid

        }), 500


# =========================================================
# RECENT FILE EVENTS
# =========================================================

@app.route("/api/events")
def events():

    try:

        rows = get_recent_events()

        data = []

        for row in rows:

            data.append({

                "id":
                    row[0],

                "event_type":
                    row[1],

                "file_path":
                    row[2],

                "timestamp":
                    row[3]

            })

        return jsonify(data)

    except Exception as error:

        return jsonify({

            "success": False,

            "message": str(error),

            "data": []

        }), 500


# =========================================================
# RECENT SECURITY ALERTS
# =========================================================

@app.route("/api/alerts")
def alerts():

    try:

        rows = get_recent_alerts()

        data = []

        for row in rows:

            data.append({

                "id":
                    row[0],

                "risk_level":
                    row[1],

                "event_count":
                    row[2],

                "message":
                    row[3],

                "timestamp":
                    row[4]

            })

        return jsonify(data)

    except Exception as error:

        return jsonify({

            "success": False,

            "message": str(error),

            "data": []

        }), 500


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/api/health")
def health():

    return jsonify({

        "status":
            "online",

        "application":
            "Ransomware Detection and Prevention System",

        "monitoring":
            monitor.monitoring

    })


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    print()

    print("=" * 60)

    print(
        "RANSOMWARE DETECTION "
        "AND PREVENTION SYSTEM"
    )

    print("=" * 60)

    print()

    print(
        "Flask server starting..."
    )

    print(
        "Protection is controlled from the dashboard."
    )

    print(
        "Default protected folder:"
    )

    print(
        os.path.expanduser("~")
    )

    print()

    print(
        "Open browser:"
    )

    print(
        "http://127.0.0.1:5000"
    )

    print()

    print("=" * 60)

    print()


    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True,

        use_reloader=False

    )