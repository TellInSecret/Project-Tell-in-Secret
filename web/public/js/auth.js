// web/public/js/auth.js

function checkAuthAndRedirect() {
    const token = localStorage.getItem('ticmsg_token');
    const currentPage = window.location.pathname;

    // 로그인된 상태라면
    if (token) {
        // 로그인 페이지에 있다면 대시보드로 이동
        if (currentPage.includes('login.html') || currentPage.includes('register.html') || currentPage === '/' || currentPage === '/index.html') {
            window.location.href = '/dashboard.html';
        }
    } else {
        // 로그인 안 된 상태라면 대시보드 접근 시 로그인 페이지로
        if (currentPage.includes('dashboard.html')) {
            window.location.href = '/login.html';
        }
    }
}

// 페이지 로드 시 체크
document.addEventListener('DOMContentLoaded', checkAuthAndRedirect);
