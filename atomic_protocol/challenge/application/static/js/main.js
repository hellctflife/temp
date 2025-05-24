document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    });
    
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'))
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl)
    });
    
    var forms = document.querySelectorAll('.needs-validation');
    Array.prototype.slice.call(forms).forEach(function (form) {
        form.addEventListener('submit', function (event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
    
    var clipboardButtons = document.querySelectorAll('.copy-to-clipboard');
    clipboardButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var textToCopy = this.getAttribute('data-clipboard-text');
            navigator.clipboard.writeText(textToCopy).then(function() {
                var originalText = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check"></i> Copied!';
                setTimeout(function() {
                    button.innerHTML = originalText;
                }, 2000);
            }, function() {
                alert('Failed to copy text');
            });
        });
    });
    
    var autoHideAlerts = document.querySelectorAll('.alert-auto-hide');
    autoHideAlerts.forEach(function(alert) {
        setTimeout(function() {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    var currentPath = window.location.pathname;
    var navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(function(link) {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
    
    var darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            document.body.classList.toggle('light-mode');
            var isDarkMode = !document.body.classList.contains('light-mode');
            localStorage.setItem('darkMode', isDarkMode ? 'enabled' : 'disabled');
        });
        
        var darkMode = localStorage.getItem('darkMode');
        if (darkMode === 'disabled') {
            document.body.classList.add('light-mode');
        }
    }
});