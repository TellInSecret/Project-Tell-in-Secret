// web/public/js/login.js
document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.querySelector('input[type="password"]');
    if (passwordInput) {
        passwordInput.addEventListener('keyup', (event) => {
            // Caps Lock 상태 확인
            if (event.getModifierState("CapsLock")) {
                // UI에 표시하거나 알림을 보냅니다.
                // 보안을 위해 너무 자세한 메시지보다는 간단한 알림을 권장합니다.
                alert("Caps Lock이 켜져 있습니다.");
            }
        });
    }
});
