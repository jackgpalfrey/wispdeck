const button = document.querySelector("#celebrate");
const status = document.querySelector("#status");

if (button && status) {
  let clicks = 0;
  button.addEventListener("click", () => {
    clicks += 1;
    status.textContent = clicks === 1
      ? "JavaScript works. The bundle is being served correctly."
      : `Still working — ${clicks} clicks and counting.`;
  });
}
