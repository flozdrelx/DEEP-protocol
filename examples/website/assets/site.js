document.querySelector("#theme-toggle").addEventListener("click", () => {
  document.body.classList.toggle("alternate");
  document.querySelector("#interaction-status").textContent = "JavaScript works here, too.";
});
fetch("./data.json?v=1")
  .then(response => { if (!response.ok) throw new Error("Resource unavailable"); return response.json(); })
  .then(data => { document.querySelector("#data-status").textContent = data.message; window.deepDemoReady = true; })
  .catch(() => { document.querySelector("#data-status").textContent = "Could not load the sample data."; });
