 document.addEventListener('DOMContentLoaded', function() {
            const navbar = document.getElementById('mainNavbar');
            const navLinks = document.querySelectorAll('.nav-link');
            
            // Smooth scrolling for anchor links
            document.querySelectorAll('a[href^="#"]').forEach(anchor => {
                anchor.addEventListener('click', function (e) {
                    e.preventDefault();
                    const target = document.querySelector(this.getAttribute('href'));
                    if (target) {
                        target.scrollIntoView({
                            behavior: 'smooth',
                            block: 'start'
                        });
                    }
                });
            });

            // Enhanced scroll behavior
            window.addEventListener('scroll', () => {
                if (window.scrollY > 50) {
                    navbar.classList.add('scrolled');
                } else {
                    navbar.classList.remove('scrolled');
                }
            });

            // Active link management
            navLinks.forEach(link => {
                link.addEventListener('click', function() {
                    navLinks.forEach(l => l.classList.remove('active'));
                    this.classList.add('active');
                });
            });

            // Mobile menu auto-close
            navLinks.forEach(link => {
                link.addEventListener('click', () => {
                    const navbarCollapse = document.getElementById('navbarNav');
                    if (navbarCollapse.classList.contains('show')) {
                        bootstrap.Collapse.getInstance(navbarCollapse).hide();
                    }
                });
            });
        });

        document.querySelectorAll('.info-card').forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(30px)';
            
            setTimeout(() => {
                card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 200);
        });

        // Fade in animation on scroll
        const observerOptions = {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        };

        const observer = new IntersectionObserver(function(entries) {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('visible');
                }
            });
        }, observerOptions);

        document.querySelectorAll('.fade-in').forEach(el => {
            observer.observe(el);
        });

        // Add loading animation
        window.addEventListener('load', function() {
            document.body.style.opacity = '0';
            document.body.style.transition = 'opacity 0.3s ease';
            setTimeout(() => {
                document.body.style.opacity = '1';
            }, 100);
        });