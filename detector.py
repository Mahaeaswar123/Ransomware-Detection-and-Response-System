import os
import time
from collections import deque, Counter
from threading import Lock

import psutil

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from database import log_event, log_alert


class RansomwareDetector(FileSystemEventHandler):

    def __init__(self):

        self.events = deque()
        self.file_events = Counter()
        self.lock = Lock()

        self.alert_cooldown = 10
        self.last_alert_time = 0

        # Risk
        self.current_risk = "LOW"

        # HIGH risk stays active until explicitly reset
        self.threat_active = False

        self.suspicious_path = None

        # Activity statistics
        self.event_count = 0
        self.unique_file_count = 0
        self.change_count = 0

        # Process information
        self.suspicious_pid = None
        self.suspicious_process = None

    # =========================================================
    # IGNORE NORMAL / GENERATED ACTIVITY
    # =========================================================

    def is_ignored_path(self, file_path):

        if not file_path:
            return True

        path = os.path.abspath(file_path).lower()

        ignored_parts = [
            "\\appdata\\",
            "\\temp\\",
            "\\tmp\\",
            "\\cache\\",
            "\\caches\\",

            "\\__pycache__\\",
            "\\.pytest_cache\\",
            "\\.mypy_cache\\",

            "\\node_modules\\",
            "\\.npm\\",
            "\\.yarn\\",

            "\\.git\\",
            "\\.idea\\",
            "\\.vscode\\",

            "\\build\\",
            "\\dist\\",
            "\\out\\",
            "\\target\\",

            "\\.gradle\\",
            "\\intermediates\\",
            "\\generated\\",
            "\\outputs\\",

            "\\.dart_tool\\",
            "\\.pub-cache\\",

            "\\coverage\\",
            "\\.next\\",
            "\\.nuxt\\",

            "\\$recycle.bin\\"
        ]

        for part in ignored_parts:

            if part in path:
                return True

        return False

    # =========================================================
    # IGNORE UNIMPORTANT FILE TYPES
    # =========================================================

    def is_ignored_extension(self, file_path):

        if not file_path:
            return True

        extension = os.path.splitext(
            file_path.lower()
        )[1]

        ignored_extensions = {
            ".tmp",
            ".temp",
            ".cache",
            ".log",
            ".swp",
            ".swo",
            ".class",
            ".pyc",
        }

        return extension in ignored_extensions

    # =========================================================
    # FIND PROCESS USING SUSPICIOUS FILE
    # =========================================================

    def find_process_using_file(self, file_path):

        if not file_path:
            return None, None

        target_path = os.path.abspath(
            file_path
        ).lower()

        try:

            for process in psutil.process_iter(
                ["pid", "name"]
            ):

                try:

                    open_files = process.open_files()

                    for opened_file in open_files:

                        if not opened_file.path:
                            continue

                        opened_path = os.path.abspath(
                            opened_file.path
                        ).lower()

                        if opened_path == target_path:

                            return (
                                process.info["pid"],
                                process.info["name"]
                            )

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess
                ):
                    continue

        except Exception as error:

            print(
                f"Process detection error: {error}"
            )

        return None, None

    # =========================================================
    # CLEAN OLD EVENTS
    # =========================================================

    def cleanup_old_events(self, current_time):

        while self.events:

            if (
                current_time -
                self.events[0][0]
                > 10
            ):

                self.events.popleft()

            else:

                break

        active_paths = {
            path
            for _, path in self.events
        }

        for path in list(
            self.file_events.keys()
        ):

            if path not in active_paths:

                del self.file_events[path]

    # =========================================================
    # CALCULATE RISK
    # =========================================================

    def calculate_risk(
        self,
        event_count,
        unique_file_count
    ):

        if (
            event_count >= 20
            and unique_file_count >= 10
        ):

            return "HIGH"

        if (
            event_count >= 10
            and unique_file_count >= 5
        ):

            return "MEDIUM"

        return "LOW"

    # =========================================================
    # RESET THREAT
    # Called after suspicious process is stopped
    # =========================================================

    def reset_threat(self):

        with self.lock:

            self.threat_active = False

            self.current_risk = "LOW"

            self.suspicious_path = None

            self.suspicious_pid = None

            self.suspicious_process = None

            self.events.clear()

            self.file_events.clear()

            self.event_count = 0

            self.unique_file_count = 0

            self.change_count = 0

            self.last_alert_time = 0

        print(
            "✅ Threat handled. Risk reset to LOW."
        )

    # =========================================================
    # RECORD FILE ACTIVITY
    # =========================================================

    def record_event(
        self,
        event_type,
        file_path
    ):

        # -----------------------------------------------------
        # Ignore invalid paths
        # -----------------------------------------------------

        if not file_path:
            return

        if os.path.isdir(file_path):
            return

        # -----------------------------------------------------
        # Ignore generated folders
        # -----------------------------------------------------

        if self.is_ignored_path(file_path):
            return

        # -----------------------------------------------------
        # Ignore temporary extensions
        # -----------------------------------------------------

        if self.is_ignored_extension(file_path):
            return

        current_time = time.time()

        with self.lock:

            # Add event
            self.events.append(
                (
                    current_time,
                    file_path
                )
            )

            # Remove events older than 10 seconds
            self.cleanup_old_events(
                current_time
            )

            # Event count
            event_count = len(
                self.events
            )

            # Unique file count
            unique_files = len({
                path
                for _, path in self.events
            })

            # File activity count
            self.file_events[
                file_path
            ] += 1

            # Most recent active file
            if self.events:

                suspicious_path = (
                    self.events[-1][1]
                )

            else:

                suspicious_path = None

            # Calculate current activity risk
            calculated_risk = self.calculate_risk(
                event_count,
                unique_files
            )

            # -------------------------------------------------
            # IMPORTANT:
            #
            # Once HIGH is detected, keep HIGH active.
            # It will NOT return to LOW automatically.
            #
            # reset_threat() must be called after response.
            # -------------------------------------------------

            if calculated_risk == "HIGH":

                self.threat_active = True

                self.current_risk = "HIGH"

                self.suspicious_path = (
                    suspicious_path
                )

            elif not self.threat_active:

                self.current_risk = calculated_risk

                if calculated_risk != "HIGH":

                    self.suspicious_path = None

                    self.suspicious_pid = None

                    self.suspicious_process = None

            # If threat_active is already True,
            # current_risk remains HIGH.

            # Save statistics
            self.event_count = event_count

            self.unique_file_count = unique_files

            self.change_count = event_count

        # =====================================================
        # DATABASE EVENT
        # =====================================================

        try:

            log_event(
                event_type,
                file_path
            )

        except Exception as error:

            print(
                f"Database event error: {error}"
            )

        # =====================================================
        # CONSOLE
        # =====================================================

        print(
            f"[{self.current_risk}] "
            f"{event_type}: "
            f"{file_path} "
            f"| Events: {event_count} "
            f"| Unique files: {unique_files}"
        )

        # =====================================================
        # ONLY HIGH RISK NEEDS PROCESS DETECTION
        # =====================================================

        if self.current_risk != "HIGH":

            return

        # -----------------------------------------------------
        # Find process using suspicious file
        # -----------------------------------------------------

        pid, process_name = (
            self.find_process_using_file(
                self.suspicious_path
            )
        )

        # -----------------------------------------------------
        # Save process information when found
        # -----------------------------------------------------

        if pid:

            self.suspicious_pid = pid

            self.suspicious_process = (
                process_name
            )

            print(
                "🔎 Suspicious process found: "
                f"{process_name} "
                f"(PID: {pid})"
            )

        # -----------------------------------------------------
        # Alert process information
        # -----------------------------------------------------

        if self.suspicious_pid:

            process_info = (
                f"Process: "
                f"{self.suspicious_process} "
                f"(PID: {self.suspicious_pid})"
            )

        else:

            process_info = (
                "Process could not be identified"
            )

        # =====================================================
        # ALERT COOLDOWN
        # =====================================================

        if (
            current_time -
            self.last_alert_time
            >= self.alert_cooldown
        ):

            message = (
                "Suspicious ransomware-like "
                f"activity detected: "
                f"{event_count} events across "
                f"{unique_files} different "
                "files in 10 seconds. "
                f"Suspicious path: "
                f"{self.suspicious_path}. "
                f"{process_info}"
            )

            try:

                log_alert(
                    "HIGH",
                    event_count,
                    message
                )

            except Exception as error:

                print(
                    f"Database alert error: {error}"
                )

            print(
                f"⚠️ HIGH RISK: {message}"
            )

            self.last_alert_time = (
                current_time
            )

    # =========================================================
    # PUBLIC RISK LEVEL
    # =========================================================

    def get_risk_level(
        self,
        event_count,
        unique_file_count=0
    ):

        return self.calculate_risk(
            event_count,
            unique_file_count
        )

    # =========================================================
    # WATCHDOG EVENTS
    # =========================================================

    def on_created(self, event):

        if not event.is_directory:

            self.record_event(
                "CREATED",
                event.src_path
            )

    def on_modified(self, event):

        if not event.is_directory:

            self.record_event(
                "MODIFIED",
                event.src_path
            )

    def on_deleted(self, event):

        if not event.is_directory:

            self.record_event(
                "DELETED",
                event.src_path
            )

    def on_moved(self, event):

        if not event.is_directory:

            self.record_event(
                "RENAMED",
                event.dest_path
            )


# =============================================================
# MONITOR
# =============================================================

class Monitor:

    def __init__(self):

        self.observer = None

        self.monitoring = False

        # Automatically monitor current Windows user folder
        self.folder = os.path.expanduser("~")

        self.detector = None

    # =========================================================
    # START MONITORING
    # =========================================================

    def start(self, folder_path=None):

        if self.monitoring:

            return False

        if not folder_path:

            folder_path = os.path.expanduser("~")

        if not os.path.isdir(folder_path):

            raise ValueError(
                f"Folder does not exist: "
                f"{folder_path}"
            )

        self.folder = os.path.abspath(
            folder_path
        )

        self.detector = (
            RansomwareDetector()
        )

        self.observer = Observer()

        self.observer.schedule(
            self.detector,
            self.folder,
            recursive=True
        )

        self.observer.start()

        self.monitoring = True

        print(
            "🛡️ Automatic monitoring started: "
            f"{self.folder}"
        )

        return True

    # =========================================================
    # STOP MONITORING
    # =========================================================

    def stop(self):

        if not self.monitoring:

            return False

        try:

            self.observer.stop()

            self.observer.join()

        except Exception as error:

            print(
                f"Monitor stop error: {error}"
            )

        self.observer = None

        self.monitoring = False

        self.detector = None

        print(
            "Monitoring stopped"
        )

        return True

    # =========================================================
    # STATUS
    # =========================================================

    def get_status(self):

        status = {

            "monitoring":
                self.monitoring,

            "folder":
                self.folder,

            "risk":
                "LOW",

            "event_count":
                0,

            "unique_file_count":
                0,

            "change_count":
                0,

            "suspicious_path":
                None,

            "suspicious_pid":
                None,

            "suspicious_process":
                None
        }

        if self.detector:

            status["risk"] = (
                self.detector.current_risk
            )

            status["event_count"] = (
                self.detector.event_count
            )

            status["unique_file_count"] = (
                self.detector.unique_file_count
            )

            status["change_count"] = (
                self.detector.change_count
            )

            status["suspicious_path"] = (
                self.detector.suspicious_path
            )

            status["suspicious_pid"] = (
                self.detector.suspicious_pid
            )

            status["suspicious_process"] = (
                self.detector.suspicious_process
            )

        return status