document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("scan-form");
  const loading = document.getElementById("loading");

  form.addEventListener("submit", function () {
    loading.style.display = "block";
  });
});
