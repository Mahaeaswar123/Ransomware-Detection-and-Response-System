// ============================================================
// RANSOMWARE DETECTION DASHBOARD
// ============================================================

let lastRisk = "LOW";


// ============================================================
// UPDATE SYSTEM STATUS
// ============================================================

async function updateStatus() {
    try {
        const response = await fetch("/api/status", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Status API failed");
        }

        const data = await response.json();

        const statusElement = document.getElementById("status");
        const folderElement = document.getElementById("folder");
        const riskElement = document.getElementById("riskLevel");
        const riskMessage = document.getElementById("riskMessage");

        const suspiciousProcess =
            document.getElementById("suspiciousProcess");

        const suspiciousPid =
            document.getElementById("suspiciousPid");

        const suspiciousPath =
            document.getElementById("suspiciousPath");

        const respondButton =
            document.getElementById("respondButton");


        // Monitoring status
        if (data.monitoring) {
            statusElement.textContent = "● Monitoring";
            statusElement.style.color = "#22c55e";
        } else {
            statusElement.textContent = "Stopped";
            statusElement.style.color = "#ef4444";
        }


        // Protected folder
        folderElement.textContent = data.folder || "None";


        // Risk level
        const risk = data.risk || "LOW";

        riskElement.classList.remove(
            "low",
            "medium",
            "high"
        );


        if (risk === "HIGH") {

            riskElement.textContent = "HIGH";
            riskElement.classList.add("high");

            riskMessage.textContent =
                `High-risk activity detected. ` +
                `${data.event_count || 0} file events across ` +
                `${data.unique_file_count || 0} files.`;

        }

        else if (risk === "MEDIUM") {

            riskElement.textContent = "MEDIUM";
            riskElement.classList.add("medium");

            riskMessage.textContent =
                `Elevated file activity detected. ` +
                `${data.event_count || 0} events across ` +
                `${data.unique_file_count || 0} files.`;

        }

        else {

            riskElement.textContent = "LOW";
            riskElement.classList.add("low");

            riskMessage.textContent =
                "System activity is normal.";
        }


        lastRisk = risk;


        // Suspicious process
        suspiciousProcess.textContent =
            data.suspicious_process || "None detected";

        suspiciousPid.textContent =
            data.suspicious_pid || "None";

        suspiciousPath.textContent =
            data.suspicious_path || "None";


        // Stop process button
        if (
            risk === "HIGH" &&
            data.suspicious_pid
        ) {
            respondButton.style.display = "inline-block";
        } else {
            respondButton.style.display = "none";
        }

    }

    catch (error) {
        console.error("Status update error:", error);
    }
}


// ============================================================
// START MONITORING
// ============================================================

async function startMonitoring() {

    try {

        const response = await fetch(
            "/api/start",
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!data.success) {

            alert(
                data.message ||
                "Unable to start monitoring."
            );

            return;
        }

        await updateStatus();
        await loadEvents();
        await loadAlerts();

    }

    catch (error) {

        console.error("Start error:", error);

        alert(
            "Unable to start monitoring."
        );
    }
}


// ============================================================
// STOP MONITORING
// ============================================================

async function stopMonitoring() {

    try {

        const response = await fetch(
            "/api/stop",
            {
                method: "POST"
            }
        );

        const data = await response.json();

        if (!data.success) {

            alert(
                data.message ||
                "Unable to stop monitoring."
            );

            return;
        }

        await updateStatus();
        await loadEvents();
        await loadAlerts();

    }

    catch (error) {

        console.error("Stop error:", error);
    }
}


// ============================================================
// LOAD FILE EVENTS
// ============================================================

async function loadEvents() {

    try {

        const response = await fetch(
            "/api/events",
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("Events API failed");
        }

        const events = await response.json();

        const table =
            document.getElementById("eventsTable");


        if (
            !Array.isArray(events) ||
            events.length === 0
        ) {

            table.innerHTML = `
                <tr>
                    <td colspan="3" class="empty">
                        No activity yet.
                    </td>
                </tr>
            `;

            return;
        }


        table.innerHTML = "";


        events.forEach(event => {

            const row =
                document.createElement("tr");

            const typeCell =
                document.createElement("td");

            const fileCell =
                document.createElement("td");

            const timeCell =
                document.createElement("td");


            // Event type
            typeCell.textContent =
                event.event_type || "UNKNOWN";


            // Event class
            if (event.event_type === "CREATED") {

                typeCell.className =
                    "event-created";

            }

            else if (event.event_type === "MODIFIED") {

                typeCell.className =
                    "event-modified";

            }

            else if (event.event_type === "DELETED") {

                typeCell.className =
                    "event-deleted";

            }

            else if (event.event_type === "RENAMED") {

                typeCell.className =
                    "event-renamed";
            }


            // File path
            fileCell.textContent =
                event.file_path || "Unknown";


            // Timestamp
            if (event.timestamp) {

                const date =
                    new Date(event.timestamp);

                timeCell.textContent =
                    date.toLocaleTimeString();

            } else {

                timeCell.textContent = "--";
            }


            row.appendChild(typeCell);
            row.appendChild(fileCell);
            row.appendChild(timeCell);

            table.appendChild(row);
        });

    }

    catch (error) {

        console.error(
            "Events error:",
            error
        );
    }
}


// ============================================================
// LOAD ALERTS
// ============================================================

async function loadAlerts() {

    try {

        const response = await fetch(
            "/api/alerts",
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("Alerts API failed");
        }

        const alerts = await response.json();

        const container =
            document.getElementById("alerts");


        if (
            !Array.isArray(alerts) ||
            alerts.length === 0
        ) {

            container.innerHTML =
                `<p class="empty">No alerts yet.</p>`;

            return;
        }


        container.innerHTML = "";


        alerts.forEach(alert => {

            const div =
                document.createElement("div");

            div.className = "alert";


            const title =
                document.createElement("strong");

            title.textContent =
                `🚨 ${alert.risk_level || "ALERT"}`;


            const message =
                document.createElement("p");

            message.textContent =
                alert.message ||
                "Suspicious activity detected.";


            const time =
                document.createElement("small");


            if (alert.timestamp) {

                time.textContent =
                    new Date(
                        alert.timestamp
                    ).toLocaleTimeString();

            } else {

                time.textContent = "--";
            }


            div.appendChild(title);
            div.appendChild(message);
            div.appendChild(time);

            container.appendChild(div);
        });

    }

    catch (error) {

        console.error(
            "Alerts error:",
            error
        );
    }
}


// ============================================================
// RESPOND TO THREAT
// ============================================================

async function respondToThreat() {

    const confirmed =
        confirm(
            "A suspicious process has been detected.\n\n" +
            "Do you want to stop the detected process?"
        );


    if (!confirmed) {
        return;
    }


    const respondButton =
        document.getElementById("respondButton");


    // Disable button while stopping process
    if (respondButton) {
        respondButton.disabled = true;
        respondButton.textContent = "Stopping...";
    }


    try {

        const response = await fetch(
            "/api/stop-process",
            {
                method: "POST"
            }
        );

        const data =
            await response.json();


        alert(
            data.message ||
            "Response completed."
        );


        await updateStatus();
        await loadEvents();
        await loadAlerts();

    }

    catch (error) {

        console.error(
            "Threat response error:",
            error
        );

        alert(
            "Unable to stop suspicious process."
        );
    }

    finally {

        // Restore button
        if (respondButton) {
            respondButton.disabled = false;
            respondButton.textContent =
                "Stop Suspicious Process";
        }
    }
}


// ============================================================
// REFRESH DASHBOARD
// ============================================================

async function refreshDashboard() {

    await updateStatus();
    await loadEvents();
    await loadAlerts();
}


// ============================================================
// INITIAL LOAD
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    () => {

        refreshDashboard();

        // Refresh every 1 second
        setInterval(
            refreshDashboard,
            1000
        );
    }
);