"use strict";


/* =========================================================
   Elements
   ========================================================= */

const registrationForm =
    document.getElementById("registration-form");

const usernameInput =
    document.getElementById("username");

const passwordInput =
    document.getElementById("password");

const confirmPasswordInput =
    document.getElementById("confirm_password");

const togglePasswordButton =
    document.getElementById("toggle-password");

const strengthDisplay =
    document.getElementById("strength-display");

const passwordMatchMessage =
    document.getElementById("password-match-message");

const rulesToggle =
    document.getElementById("rules-toggle");

const passwordRulesPanel =
    document.getElementById("password-rules-panel");


const humanCheck =
    document.getElementById("human_check");

const robotCheckRow =
    document.getElementById("robot-check-row");

const robotStatus =
    document.getElementById("robot-status");

const robotBrandIcon =
    document.getElementById("robot-brand-icon");


const captchaModal =
    document.getElementById("captcha-modal");

const captchaBackdrop =
    document.getElementById("captcha-backdrop");

const closeCaptchaButton =
    document.getElementById("close-captcha");

const cancelCaptchaButton =
    document.getElementById("cancel-captcha");

const confirmCaptchaButton =
    document.getElementById("confirm-captcha");

const captchaImage =
    document.getElementById("captcha-image");

const refreshCaptchaButton =
    document.getElementById("refresh-captcha");

const captchaAnswer =
    document.getElementById("captcha_answer");

const captchaClientMessage =
    document.getElementById("captcha-client-message");


const rules = {
    length: document.getElementById("rule-length"),
    lowercase: document.getElementById("rule-lowercase"),
    uppercase: document.getElementById("rule-uppercase"),
    number: document.getElementById("rule-number"),
    special: document.getElementById("rule-special"),
    common: document.getElementById("rule-common"),
    username: document.getElementById("rule-username"),
    sequence: document.getElementById("rule-sequence"),
    repetition: document.getElementById("rule-repetition"),
    spaces: document.getElementById("rule-spaces")
};


const commonPasswords = new Set([
    "123456",
    "12345678",
    "123456789",
    "password",
    "password1",
    "qwerty",
    "qwerty123",
    "admin",
    "administrator",
    "letmein",
    "welcome",
    "welcome123",
    "iloveyou",
    "abc123",
    "monkey",
    "dragon",
    "football"
]);


const obviousSequences = [
    "012345",
    "123456",
    "234567",
    "345678",
    "456789",
    "987654",
    "876543",
    "765432",
    "abcdef",
    "bcdefg",
    "qwerty",
    "asdfgh",
    "zxcvbn"
];


let captchaChallengeVerified = false;
let modalCloseTimer = null;


/* =========================================================
   Password requirements
   ========================================================= */

function getRuleLabel(element) {
    if (!element.dataset.label) {
        element.dataset.label =
            element.textContent
                .replace(/^[✓✗○]\s*/, "")
                .trim();
    }

    return element.dataset.label;
}


function updateRule(element, passed) {
    if (!element) {
        return;
    }

    const label = getRuleLabel(element);

    element.classList.remove(
        "rule-passed",
        "rule-failed",
        "rule-neutral"
    );

    if (passed === null) {
        element.textContent = `○ ${label}`;

        element.classList.add(
            "rule-neutral"
        );

        return;
    }

    element.textContent =
        `${passed ? "✓" : "✗"} ${label}`;

    element.classList.add(
        passed
            ? "rule-passed"
            : "rule-failed"
    );
}


function containsObviousSequence(password) {
    const lowerPassword =
        password.toLowerCase();

    return obviousSequences.some(
        sequence =>
            lowerPassword.includes(sequence)
    );
}


function containsRepeatedCharacters(password) {
    return /(.)\1{3,}/.test(password);
}


function evaluatePassword() {
    const password =
        passwordInput.value;

    const username =
        usernameInput.value
            .trim()
            .toLowerCase();

    const lowerPassword =
        password.toLowerCase();

    if (!password) {
        Object.values(rules).forEach(
            rule =>
                updateRule(
                    rule,
                    null
                )
        );

        strengthDisplay.textContent =
            "Password strength: Not evaluated";

        strengthDisplay.className =
            "strength-display";

        return;
    }

    const containsUsername =
        username.length >= 3
        && lowerPassword.includes(username);

    const checks = {
        length:
            password.length >= 12
            && password.length <= 128,

        lowercase:
            /[a-z]/.test(password),

        uppercase:
            /[A-Z]/.test(password),

        number:
            /\d/.test(password),

        special:
            /[^A-Za-z0-9]/.test(password),

        common:
            !commonPasswords.has(
                lowerPassword
            ),

        username:
            !containsUsername,

        sequence:
            !containsObviousSequence(
                password
            ),

        repetition:
            !containsRepeatedCharacters(
                password
            ),

        spaces:
            password === password.trim()
    };

    Object.keys(checks).forEach(
        ruleName => {
            updateRule(
                rules[ruleName],
                checks[ruleName]
            );
        }
    );

    let score = 0;

    if (password.length >= 8) {
        score += 1;
    }

    if (password.length >= 12) {
        score += 1;
    }

    if (password.length >= 16) {
        score += 1;
    }

    const hasLowercase =
        /[a-z]/.test(password);

    const hasUppercase =
        /[A-Z]/.test(password);

    const hasNumber =
        /\d/.test(password);

    const hasSpecial =
        /[^A-Za-z0-9]/.test(password);

    score += Number(hasLowercase);
    score += Number(hasUppercase);
    score += Number(hasNumber);
    score += Number(hasSpecial);

    const characterTypeCount = [
        hasLowercase,
        hasUppercase,
        hasNumber,
        hasSpecial
    ].filter(Boolean).length;

    if (characterTypeCount === 4) {
        score += 1;
    }

    if (
        commonPasswords.has(
            lowerPassword
        )
    ) {
        score -= 4;
    }

    if (containsUsername) {
        score -= 2;
    }

    if (
        containsObviousSequence(
            password
        )
    ) {
        score -= 2;
    }

    if (
        containsRepeatedCharacters(
            password
        )
    ) {
        score -= 1;
    }

    score = Math.max(
        0,
        Math.min(
            score,
            8
        )
    );

    let strength = "Weak";

    if (score >= 7) {
        strength = "Strong";

    } else if (score >= 5) {
        strength = "Good";

    } else if (score >= 3) {
        strength = "Fair";
    }

    const allRequirementsPassed =
        Object.values(checks)
            .every(Boolean);

    strengthDisplay.textContent =
        `Password strength: ${strength} (${score}/8)`;

    strengthDisplay.className =
        "strength-display";

    strengthDisplay.classList.add(
        `strength-${strength.toLowerCase()}`
    );

    if (allRequirementsPassed) {
        strengthDisplay.textContent +=
            " — All requirements passed";
    }
}


/* =========================================================
   Password rules animation
   ========================================================= */

function setRulesPanel(openPanel) {
    passwordRulesPanel.classList.toggle(
        "is-open",
        openPanel
    );

    rulesToggle.classList.toggle(
        "is-active",
        openPanel
    );

    rulesToggle.setAttribute(
        "aria-expanded",
        String(openPanel)
    );

    passwordRulesPanel.setAttribute(
        "aria-hidden",
        String(!openPanel)
    );

    rulesToggle.title =
        openPanel
            ? "Hide password requirements"
            : "Show password requirements";
}


function toggleRulesPanel() {
    const currentlyOpen =
        rulesToggle.getAttribute(
            "aria-expanded"
        ) === "true";

    setRulesPanel(
        !currentlyOpen
    );
}


/* =========================================================
   Password confirmation
   ========================================================= */

function checkPasswordMatch() {
    const password =
        passwordInput.value;

    const confirmation =
        confirmPasswordInput.value;

    passwordMatchMessage.className = "";

    if (!confirmation) {
        passwordMatchMessage.textContent =
            "Re-enter the same password.";

        return;
    }

    if (password === confirmation) {
        passwordMatchMessage.textContent =
            "✓ Passwords match.";

        passwordMatchMessage.classList.add(
            "match-success"
        );

    } else {
        passwordMatchMessage.textContent =
            "✗ Passwords do not match.";

        passwordMatchMessage.classList.add(
            "match-error"
        );
    }
}


/* =========================================================
   Show and hide password
   ========================================================= */

function togglePasswordVisibility() {
    const shouldShow =
        passwordInput.type
        === "password";

    passwordInput.type =
        shouldShow
            ? "text"
            : "password";

    confirmPasswordInput.type =
        shouldShow
            ? "text"
            : "password";

    togglePasswordButton.textContent =
        shouldShow
            ? "Hide"
            : "Show";

    togglePasswordButton.setAttribute(
        "aria-label",
        shouldShow
            ? "Hide password"
            : "Show password"
    );
}


/* =========================================================
   CAPTCHA modal
   ========================================================= */

function showCaptchaMessage(
    message,
    isError = false
) {
    captchaClientMessage.textContent =
        message;

    captchaClientMessage.className =
        "captcha-client-message";

    if (message) {
        captchaClientMessage.classList.add(
            isError
                ? "captcha-message-error"
                : "captcha-message-success"
        );
    }
}


function refreshCaptcha() {
    const captchaUrl =
        captchaImage.dataset.captchaUrl;

    captchaImage.src =
        `${captchaUrl}?v=${Date.now()}`;

    captchaAnswer.disabled = false;
    captchaAnswer.value = "";

    captchaChallengeVerified = false;

    humanCheck.checked = false;

    robotCheckRow.classList.remove(
        "robot-challenge-ready"
    );

    robotStatus.textContent =
        "Complete the image challenge";

    showCaptchaMessage("");

    window.setTimeout(
        () => {
            captchaAnswer.focus();
        },
        100
    );
}


function openCaptchaModal(
    loadNewCaptcha = true
) {
    if (modalCloseTimer) {
        window.clearTimeout(
            modalCloseTimer
        );

        modalCloseTimer = null;
    }

    captchaModal.hidden = false;

    captchaModal.setAttribute(
        "aria-hidden",
        "false"
    );

    document.body.classList.add(
        "modal-open"
    );

    window.requestAnimationFrame(
        () => {
            captchaModal.classList.add(
                "is-visible"
            );
        }
    );

    if (loadNewCaptcha) {
        refreshCaptcha();

    } else {
        captchaAnswer.disabled = false;

        window.setTimeout(
            () => {
                captchaAnswer.focus();
            },
            100
        );
    }
}


function hideCaptchaModal() {
    captchaModal.classList.remove(
        "is-visible"
    );

    captchaModal.setAttribute(
        "aria-hidden",
        "true"
    );

    document.body.classList.remove(
        "modal-open"
    );

    modalCloseTimer =
        window.setTimeout(
            () => {
                captchaModal.hidden = true;
                modalCloseTimer = null;
            },
            220
        );
}


function cancelCaptchaChallenge() {
    humanCheck.checked = false;

    captchaChallengeVerified = false;

    captchaAnswer.value = "";
    captchaAnswer.disabled = true;

    captchaImage.removeAttribute(
        "src"
    );

    robotCheckRow.classList.remove(
        "robot-challenge-ready"
    );

    robotStatus.textContent =
        "Click to begin verification";

    showCaptchaMessage("");

    hideCaptchaModal();
}


async function confirmCaptchaChallenge() {
    const answer =
        captchaAnswer.value.trim();

    if (
        !/^[A-Za-z0-9]{6}$/.test(
            answer
        )
    ) {
        showCaptchaMessage(
            "Enter all six CAPTCHA characters before continuing.",
            true
        );

        captchaAnswer.focus();

        return;
    }

    const csrfTokenInput =
        registrationForm.querySelector(
            'input[name="csrf_token"]'
        );

    if (!csrfTokenInput) {
        showCaptchaMessage(
            "The security token is unavailable. Refresh the page.",
            true
        );

        return;
    }

    confirmCaptchaButton.disabled =
        true;

    confirmCaptchaButton.textContent =
        "Verifying...";

    const requestBody =
        new URLSearchParams();

    requestBody.set(
        "captcha_answer",
        answer
    );

    requestBody.set(
        "csrf_token",
        csrfTokenInput.value
    );

    try {
        const response =
            await fetch(
                "/verify-captcha",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/x-www-form-urlencoded;charset=UTF-8",

                        "X-Requested-With":
                            "XMLHttpRequest"
                    },

                    body:
                        requestBody.toString()
                }
            );

        const result =
            await response.json();

        if (
            !response.ok
            || !result.success
        ) {
            captchaChallengeVerified =
                false;

            humanCheck.checked = false;

            robotCheckRow.classList.remove(
                "robot-challenge-ready"
            );

            robotStatus.textContent =
                "Verification failed — try again";

            if (
                result.refresh_required
            ) {
                refreshCaptcha();
            }

            showCaptchaMessage(
                result.message
                || "The CAPTCHA answer is incorrect.",
                true
            );

            captchaAnswer.focus();

            return;
        }

        captchaChallengeVerified = true;

        humanCheck.checked = true;

        robotCheckRow.classList.add(
            "robot-challenge-ready"
        );

        robotStatus.textContent =
            "Human verification completed";

        robotBrandIcon.textContent =
            "✓";

        showCaptchaMessage(
            result.message,
            false
        );

        window.setTimeout(
            hideCaptchaModal,
            450
        );

    } catch (error) {
        captchaChallengeVerified =
            false;

        humanCheck.checked = false;

        robotStatus.textContent =
            "Verification could not be completed";

        showCaptchaMessage(
            "The CAPTCHA could not be verified. Try again.",
            true
        );

    } finally {
        confirmCaptchaButton.disabled =
            false;

        confirmCaptchaButton.textContent =
            "Confirm Challenge";
    }
}


/* =========================================================
   Human checkbox
   ========================================================= */

function handleHumanCheckChange() {
    if (humanCheck.checked) {
        openCaptchaModal(true);

    } else {
        cancelCaptchaChallenge();
    }
}


/* =========================================================
   Form submission
   ========================================================= */

function validateHumanChallengeBeforeSubmit(
    event
) {
    if (!captchaChallengeVerified) {
        event.preventDefault();

        humanCheck.checked = true;

        openCaptchaModal(
            !captchaImage.src
        );

        showCaptchaMessage(
            "Verify the CAPTCHA answer before creating the account.",
            true
        );
    }
}


/* =========================================================
   Events
   ========================================================= */

rulesToggle.addEventListener(
    "click",
    toggleRulesPanel
);


togglePasswordButton.addEventListener(
    "click",
    togglePasswordVisibility
);


usernameInput.addEventListener(
    "input",
    evaluatePassword
);


passwordInput.addEventListener(
    "input",
    () => {
        evaluatePassword();
        checkPasswordMatch();
    }
);


confirmPasswordInput.addEventListener(
    "input",
    checkPasswordMatch
);


humanCheck.addEventListener(
    "change",
    handleHumanCheckChange
);


refreshCaptchaButton.addEventListener(
    "click",
    refreshCaptcha
);


confirmCaptchaButton.addEventListener(
    "click",
    confirmCaptchaChallenge
);


cancelCaptchaButton.addEventListener(
    "click",
    cancelCaptchaChallenge
);


closeCaptchaButton.addEventListener(
    "click",
    cancelCaptchaChallenge
);


captchaBackdrop.addEventListener(
    "click",
    cancelCaptchaChallenge
);


captchaAnswer.addEventListener(
    "input",
    () => {
        captchaAnswer.value =
            captchaAnswer.value
                .replace(/\s/g, "")
                .toUpperCase();

        captchaChallengeVerified =
            false;

        humanCheck.checked =
            false;

        robotCheckRow.classList.remove(
            "robot-challenge-ready"
        );

        showCaptchaMessage("");
    }
);


captchaAnswer.addEventListener(
    "keydown",
    event => {
        if (event.key === "Enter") {
            event.preventDefault();

            confirmCaptchaChallenge();
        }
    }
);


document.addEventListener(
    "keydown",
    event => {
        if (
            event.key === "Escape"
            && !captchaModal.hidden
        ) {
            cancelCaptchaChallenge();
        }
    }
);


registrationForm.addEventListener(
    "submit",
    validateHumanChallengeBeforeSubmit
);


/* =========================================================
   Initial display
   ========================================================= */

setRulesPanel(false);
evaluatePassword();
checkPasswordMatch();