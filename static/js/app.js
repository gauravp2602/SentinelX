function updateClock(){const el=document.getElementById("clock");if(el){el.textContent=new Date().toLocaleString("en-IN",{dateStyle:"medium",timeStyle:"medium"});}}
updateClock();setInterval(updateClock,1000);
