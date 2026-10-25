"use strict";

document.addEventListener(
    "DOMContentLoaded",
    () => {
        const csrfMeta = document.querySelector(
            'meta[name="csrf-token"]'
        );

        const csrfToken = csrfMeta
            ? csrfMeta.content
            : "";

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

        function initialiseSessionTimeout() {
            const controller = document.getElementById(
                "session-timeout-controller"
            );

            if (!controller) {
                return;
            }

            const countdownElement = document.getElementById(
                "session-countdown"
            );

            const countdownCard = document.getElementById(
                "session-countdown-card"
            );

            const timeoutSwitch = document.getElementById(
                "timeout-switch"
            );

            const timeoutButtons = Array.from(
                document.querySelectorAll(
                    "[data-timeout-mode]"
                )
            );

            const expireForm = document.getElementById(
                "session-expire-form"
            );

            if (
                !countdownElement
                || !countdownCard
                || !timeoutSwitch
            ) {
                return;
            }

            const heartbeatUrl =
                controller.dataset.heartbeatUrl;

            const setModeUrl =
                controller.dataset.setModeUrl;

            const loginUrl =
                controller.dataset.loginUrl;

            let currentMode =
                controller.dataset.currentMode
                || "standard";

            let timeoutSeconds = Number.parseInt(
                controller.dataset.timeoutSeconds,
                10
            );

            let remainingSeconds = Number.parseInt(
                controller.dataset.remainingSeconds,
                10
            );

            if (
                Number.isNaN(timeoutSeconds)
                || timeoutSeconds <= 0
            ) {
                timeoutSeconds = 900;
            }

            if (
                Number.isNaN(remainingSeconds)
                || remainingSeconds < 0
            ) {
                remainingSeconds =
                    timeoutSeconds;
            }

            let deadline =
                Date.now()
                + remainingSeconds * 1000;

            let heartbeatInProgress = false;
            let modeChangeInProgress = false;
            let expirationStarted = false;
            let lastHeartbeatSentAt = 0;
            let lastModeChangeAt = 0;

            const HEARTBEAT_THROTTLE_MS = 2000;
            const MODE_CHANGE_COOLDOWN_MS = 500;

            function updateCountdownAppearance(
                secondsLeft
            ) {
                countdownCard.classList.remove(
                    "session-countdown-warning",
                    "session-countdown-danger"
                );

                if (secondsLeft <= 10) {
                    countdownCard.classList.add(
                        "session-countdown-danger"
                    );
                } else if (secondsLeft <= 60) {
                    countdownCard.classList.add(
                        "session-countdown-warning"
                    );
                }
            }

            function updateModeVisuals(
                selectedMode
            ) {
                currentMode = selectedMode;

                timeoutSwitch.classList.toggle(
                    "is-demo",
                    selectedMode === "demo"
                );

                timeoutButtons.forEach(
                    (button) => {
                        const isSelected = (
                            button.dataset.timeoutMode
                            === selectedMode
                        );

                        button.setAttribute(
                            "aria-pressed",
                            isSelected
                                ? "true"
                                : "false"
                        );
                    }
                );
            }

            function submitExpirationForm() {
                if (expirationStarted) {
                    return;
                }

                expirationStarted = true;

                countdownElement.textContent =
                    "00:00";

                countdownCard.classList.remove(
                    "session-countdown-warning"
                );

                countdownCard.classList.add(
                    "session-countdown-danger"
                );

                timeoutButtons.forEach(
                    (button) => {
                        button.disabled = true;
                    }
                );

                if (expireForm) {
                    window.HTMLFormElement.prototype.submit.call(
                        expireForm
                    );

                    return;
                }

                window.location.assign(
                    loginUrl
                );
            }

            function renderCountdown() {
                if (expirationStarted) {
                    return;
                }

                const millisecondsLeft =
                    deadline - Date.now();

                const secondsLeft = Math.max(
                    0,
                    Math.ceil(
                        millisecondsLeft / 1000
                    )
                );

                countdownElement.textContent =
                    formatTime(
                        secondsLeft
                    );

                updateCountdownAppearance(
                    secondsLeft
                );

                if (millisecondsLeft <= 0) {
                    submitExpirationForm();
                }
            }

            function resetLocalCountdown() {
                deadline =
                    Date.now()
                    + timeoutSeconds * 1000;

                renderCountdown();
            }

            async function sendHeartbeat() {
                if (
                    heartbeatInProgress
                    || expirationStarted
                    || modeChangeInProgress
                ) {
                    return;
                }

                heartbeatInProgress = true;
                lastHeartbeatSentAt =
                    Date.now();

                const modeWhenRequestStarted =
                    currentMode;

                try {
                    const response = await fetch(
                        heartbeatUrl,
                        {
                            method: "POST",
                            credentials:
                                "same-origin",
                            cache: "no-store",
                            redirect: "follow",

                            headers: {
                                "X-CSRFToken":
                                    csrfToken,

                                "X-Requested-With":
                                    "XMLHttpRequest",

                                "Accept":
                                    "application/json",
                            },
                        }
                    );

                    if (response.redirected) {
                        window.location.assign(
                            response.url
                        );

                        return;
                    }

                    const responseType =
                        response.headers.get(
                            "content-type"
                        )
                        || "";

                    if (
                        !responseType.includes(
                            "application/json"
                        )
                    ) {
                        return;
                    }

                    const data =
                        await response.json();

                    if (!response.ok) {
                        return;
                    }

                    if (
                        modeWhenRequestStarted
                        !== currentMode
                    ) {
                        return;
                    }

                    if (
                        data.success
                        && Number.isFinite(
                            Number(
                                data.remaining_seconds
                            )
                        )
                    ) {
                        timeoutSeconds = Number(
                            data.remaining_seconds
                        );

                        deadline =
                            Date.now()
                            + timeoutSeconds * 1000;

                        renderCountdown();
                    }
                } catch (error) {
                    console.warn(
                        "Session heartbeat failed.",
                        error
                    );
                } finally {
                    heartbeatInProgress = false;
                }
            }

            async function changeTimeoutMode(
                selectedMode
            ) {
                const currentTime =
                    Date.now();

                if (
                    modeChangeInProgress
                    || expirationStarted
                    || selectedMode === currentMode
                    || (
                        currentTime
                        - lastModeChangeAt
                        < MODE_CHANGE_COOLDOWN_MS
                    )
                ) {
                    return;
                }

                lastModeChangeAt =
                    currentTime;

                modeChangeInProgress =
                    true;

                timeoutSwitch.classList.add(
                    "is-changing"
                );

                timeoutButtons.forEach(
                    (button) => {
                        button.disabled = true;
                    }
                );

                try {
                    const formData =
                        new URLSearchParams();

                    formData.set(
                        "timeout_mode",
                        selectedMode
                    );

                    const response = await fetch(
                        setModeUrl,
                        {
                            method: "POST",
                            credentials:
                                "same-origin",
                            cache: "no-store",
                            redirect: "follow",

                            headers: {
                                "Content-Type":
                                    "application/x-www-form-urlencoded;charset=UTF-8",

                                "X-CSRFToken":
                                    csrfToken,

                                "X-Requested-With":
                                    "XMLHttpRequest",

                                "Accept":
                                    "application/json",
                            },

                            body:
                                formData.toString(),
                        }
                    );

                    if (response.redirected) {
                        window.location.assign(
                            response.url
                        );

                        return;
                    }

                    const responseType =
                        response.headers.get(
                            "content-type"
                        )
                        || "";

                    if (
                        !responseType.includes(
                            "application/json"
                        )
                    ) {
                        throw new Error(
                            "Unexpected server response."
                        );
                    }

                    const data =
                        await response.json();

                    if (
                        !response.ok
                        || !data.success
                    ) {
                        throw new Error(
                            data.message
                            || "Timeout mode could not be changed."
                        );
                    }

                    const newTimeoutSeconds =
                        Number(
                            data.timeout_seconds
                        );

                    const newRemainingSeconds =
                        Number(
                            data.remaining_seconds
                        );

                    if (
                        !Number.isFinite(
                            newTimeoutSeconds
                        )
                        || newTimeoutSeconds <= 0
                    ) {
                        throw new Error(
                            "The server returned an invalid timeout."
                        );
                    }

                    timeoutSeconds =
                        newTimeoutSeconds;

                    remainingSeconds = (
                        Number.isFinite(
                            newRemainingSeconds
                        )
                        && newRemainingSeconds >= 0
                    )
                        ? newRemainingSeconds
                        : timeoutSeconds;

                    deadline =
                        Date.now()
                        + remainingSeconds * 1000;

                    updateModeVisuals(
                        data.timeout_mode
                    );

                    renderCountdown();
                } catch (error) {
                    console.error(
                        "Timeout mode change failed.",
                        error
                    );
                } finally {
                    timeoutSwitch.classList.remove(
                        "is-changing"
                    );

                    timeoutButtons.forEach(
                        (button) => {
                            button.disabled =
                                false;
                        }
                    );

                    modeChangeInProgress =
                        false;
                }
            }

            function handleUserActivity(
                event
            ) {
                if (
                    expirationStarted
                    || modeChangeInProgress
                ) {
                    return;
                }

                if (
                    event.target instanceof Element
                    && event.target.closest(
                        "#timeout-switch"
                    )
                ) {
                    return;
                }

                resetLocalCountdown();

                const currentTime =
                    Date.now();

                if (
                    currentTime
                    - lastHeartbeatSentAt
                    >= HEARTBEAT_THROTTLE_MS
                ) {
                    void sendHeartbeat();
                }
            }

            timeoutButtons.forEach(
                (button) => {
                    button.addEventListener(
                        "click",
                        (event) => {
                            event.preventDefault();
                            event.stopPropagation();

                            const selectedMode =
                                button.dataset
                                    .timeoutMode;

                            if (selectedMode) {
                                void changeTimeoutMode(
                                    selectedMode
                                );
                            }
                        }
                    );
                }
            );

            const activityEvents = [
                "mousemove",
                "mousedown",
                "keydown",
                "touchstart",
                "scroll",
            ];

            activityEvents.forEach(
                (eventName) => {
                    window.addEventListener(
                        eventName,
                        handleUserActivity,
                        {
                            passive: true,
                        }
                    );
                }
            );

            document.addEventListener(
                "visibilitychange",
                () => {
                    if (
                        document.visibilityState
                        === "visible"
                    ) {
                        renderCountdown();
                    }
                }
            );

            window.addEventListener(
                "pageshow",
                (event) => {
                    if (event.persisted) {
                        window.location.reload();
                    }
                }
            );

            window.setInterval(
                renderCountdown,
                250
            );

            updateModeVisuals(
                currentMode
            );

            renderCountdown();
        }

        function initialiseLockoutModeSwitch() {
            const controller = document.getElementById(
                "lockout-mode-controller"
            );

            const lockoutSwitch = document.getElementById(
                "lockout-switch"
            );

            if (
                !controller
                || !lockoutSwitch
            ) {
                return;
            }

            const lockoutButtons = Array.from(
                document.querySelectorAll(
                    "[data-lockout-mode]"
                )
            );

            const setModeUrl =
                controller.dataset.setModeUrl;

            let currentMode =
                controller.dataset.currentMode
                || "standard";

            let changeInProgress = false;
            let lastChangeAt = 0;

            const MODE_CHANGE_COOLDOWN_MS =
                500;

            function updateVisuals(
                selectedMode
            ) {
                currentMode = selectedMode;

                lockoutSwitch.classList.toggle(
                    "is-demo",
                    selectedMode === "demo"
                );

                lockoutButtons.forEach(
                    (button) => {
                        const isSelected = (
                            button.dataset.lockoutMode
                            === selectedMode
                        );

                        button.setAttribute(
                            "aria-pressed",
                            isSelected
                                ? "true"
                                : "false"
                        );
                    }
                );
            }

            async function changeMode(
                selectedMode
            ) {
                const currentTime =
                    Date.now();

                if (
                    changeInProgress
                    || selectedMode === currentMode
                    || (
                        currentTime
                        - lastChangeAt
                        < MODE_CHANGE_COOLDOWN_MS
                    )
                ) {
                    return;
                }

                changeInProgress = true;
                lastChangeAt = currentTime;

                lockoutSwitch.classList.add(
                    "is-changing"
                );

                lockoutButtons.forEach(
                    (button) => {
                        button.disabled = true;
                    }
                );

                try {
                    const formData =
                        new URLSearchParams();

                    formData.set(
                        "lockout_mode",
                        selectedMode
                    );

                    const response = await fetch(
                        setModeUrl,
                        {
                            method: "POST",
                            credentials:
                                "same-origin",
                            cache: "no-store",
                            redirect: "follow",

                            headers: {
                                "Content-Type":
                                    "application/x-www-form-urlencoded;charset=UTF-8",

                                "X-CSRFToken":
                                    csrfToken,

                                "X-Requested-With":
                                    "XMLHttpRequest",

                                "Accept":
                                    "application/json",
                            },

                            body:
                                formData.toString(),
                        }
                    );

                    if (response.redirected) {
                        window.location.assign(
                            response.url
                        );

                        return;
                    }

                    const responseType =
                        response.headers.get(
                            "content-type"
                        )
                        || "";

                    if (
                        !responseType.includes(
                            "application/json"
                        )
                    ) {
                        throw new Error(
                            "Unexpected server response."
                        );
                    }

                    const data =
                        await response.json();

                    if (
                        !response.ok
                        || !data.success
                    ) {
                        throw new Error(
                            data.message
                            || "Lockout mode could not be changed."
                        );
                    }

                    updateVisuals(
                        data.lockout_mode
                    );
                } catch (error) {
                    console.error(
                        "Lockout mode change failed.",
                        error
                    );
                } finally {
                    lockoutSwitch.classList.remove(
                        "is-changing"
                    );

                    lockoutButtons.forEach(
                        (button) => {
                            button.disabled =
                                false;
                        }
                    );

                    changeInProgress = false;
                }
            }

            lockoutButtons.forEach(
                (button) => {
                    button.addEventListener(
                        "click",
                        (event) => {
                            event.preventDefault();

                            const selectedMode =
                                button.dataset
                                    .lockoutMode;

                            if (selectedMode) {
                                void changeMode(
                                    selectedMode
                                );
                            }
                        }
                    );
                }
            );

            updateVisuals(
                currentMode
            );
        }

        function initialisePasswordChangeCooldown() {
            const card = document.getElementById(
                "password-change-security-card"
            );

            if (!card) {
                return;
            }

            const countdownBadge = document.getElementById(
                "password-change-countdown-badge"
            );

            const changePasswordButton =
                document.getElementById(
                    "change-password-button"
                );

            const attemptsElement =
                document.getElementById(
                    "password-change-attempts-remaining"
                );

            if (
                !countdownBadge
                || !changePasswordButton
            ) {
                return;
            }

            const isLocked =
                card.dataset.locked
                === "true";

            const remainingSeconds =
                Number.parseInt(
                    card.dataset.remainingSeconds,
                    10
                );

            const maxAttempts =
                Number.parseInt(
                    card.dataset.maxAttempts,
                    10
                );

            const changePasswordUrl =
                card.dataset.changePasswordUrl;

            if (
                !isLocked
                || Number.isNaN(
                    remainingSeconds
                )
                || remainingSeconds <= 0
            ) {
                return;
            }

            const deadline =
                Date.now()
                + remainingSeconds * 1000;

            function unlockButton() {
                countdownBadge.classList.add(
                    "is-hidden"
                );

                countdownBadge.textContent =
                    "00:00";

                changePasswordButton.classList.remove(
                    "is-disabled"
                );

                changePasswordButton.removeAttribute(
                    "aria-disabled"
                );

                changePasswordButton.removeAttribute(
                    "tabindex"
                );

                changePasswordButton.setAttribute(
                    "href",
                    changePasswordUrl
                );

                changePasswordButton.textContent =
                    "Change Password Securely";

                if (
                    attemptsElement
                    && Number.isFinite(
                        maxAttempts
                    )
                ) {
                    attemptsElement.textContent =
                        String(
                            maxAttempts
                        );
                }
            }

            function renderCooldown() {
                const millisecondsLeft =
                    deadline - Date.now();

                const secondsLeft = Math.max(
                    0,
                    Math.ceil(
                        millisecondsLeft / 1000
                    )
                );

                countdownBadge.textContent =
                    formatTime(
                        secondsLeft
                    );

                if (millisecondsLeft <= 0) {
                    unlockButton();

                    window.clearInterval(
                        intervalId
                    );
                }
            }

            const intervalId =
                window.setInterval(
                    renderCooldown,
                    250
                );

            renderCooldown();
        }

        initialiseSessionTimeout();
        initialiseLockoutModeSwitch();
        initialisePasswordChangeCooldown();
    }
);