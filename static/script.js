document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("scan-form");
  const loading = document.getElementById("loading");

  form.addEventListener("submit", function () {
    loading.style.display = "block"; // Show loading
  });

  window.onload = function () {
    loading.style.display = "none"; // Hide loading after page refresh
  };
});
