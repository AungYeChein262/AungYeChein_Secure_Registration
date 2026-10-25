"use strict";

document.addEventListener(
    "DOMContentLoaded",
    () => {
        const panel = document.getElementById(
            "login-lockout-panel"
        );

        if (!panel) {
            return;
        }

        const countdown = document.getElementById(
            "login-lockout-countdown"
        );

        const loginUrl =
            panel.dataset.loginUrl;

        let remainingSeconds = Number.parseInt(
            panel.dataset.remainingSeconds,
            10
        );

        if (
            Number.isNaN(remainingSeconds)
            || remainingSeconds <= 0
        ) {
            return;
        }

        const deadline =
            Date.now()
            + remainingSeconds * 1000;

        function formatTime(
            totalSeconds
        ) {
            const safeSeconds = Math.max(
                0,
                Math.ceil(totalSeconds)
            );

            const minutes = Math.floor(
                safeSeconds / 60
            );

            const seconds =
                safeSeconds % 60;

            return (
                String(minutes).padStart(2, "0")
                + ":"
                + String(seconds).padStart(2, "0")
            );
        }

        function render() {
            const millisecondsLeft =
                deadline - Date.now();

            const secondsLeft = Math.max(
                0,
                Math.ceil(
                    millisecondsLeft / 1000
                )
            );

            countdown.textContent =
                formatTime(
                    secondsLeft
                );

            if (millisecondsLeft <= 0) {
                window.location.replace(
                    loginUrl
                );
            }
        }

        window.setInterval(
            render,
            250
        );

        render();
    }
);