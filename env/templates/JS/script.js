document.addEventListener('DOMContentLoaded', function () {
    const menu= document.getElementById('menu');
    const htopnav = document.getElementById('htopnav');
    const icon= document.getElementById('bar');

    menu.addEventListener("click", function () {
        icon.classList.toggle('animate');
        htopnav.classList.toggle('visible');
    }); 

    icon.addEventListener("click", function () {
        icon.classList.toggle('visible');
    });
});