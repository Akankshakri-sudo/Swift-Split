const API = "http://127.0.0.1:8000";

function showSplit() {
    document.getElementById("splitSection").style.display = "flex";
    document.getElementById("mergeSection").style.display = "none";
}

function showMerge() {
    document.getElementById("splitSection").style.display = "none";
    document.getElementById("mergeSection").style.display = "flex";
}

document.getElementById("splitEncrypt").addEventListener("change", function() {
    document.getElementById("splitPassword").style.display =
        this.checked ? "block" : "none";
});

document.getElementById("mergeEncrypt").addEventListener("change", function() {
    document.getElementById("mergePassword").style.display =
        this.checked ? "block" : "none";
});

async function splitFile() {
    const file = document.getElementById("splitFile").files[0];
    const parts = document.getElementById("parts").value;
    const encrypt = document.getElementById("splitEncrypt").checked;
    const password = document.getElementById("splitPassword").value;

    const formData = new FormData();
    formData.append("file", file);
    formData.append("parts", parts);
    formData.append("encrypt", encrypt);
    formData.append("password", password);

    const response = await fetch(API + "/split", {
        method: "POST",
        body: formData
    });

    const result = await response.json();
    alert(result.message || result.error);
}

async function mergeFiles() {
    const files = document.getElementById("mergeFiles").files;
    const outputName = document.getElementById("outputName").value;
    const encrypted = document.getElementById("mergeEncrypt").checked;
    const password = document.getElementById("mergePassword").value;

    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
        formData.append("files", files[i]);
    }

    formData.append("output_name", outputName);
    formData.append("encrypted", encrypted);
    formData.append("password", password);

    const response = await fetch(API + "/merge", {
        method: "POST",
        body: formData
    });

    const result = await response.json();
    if(result.error){
    alert("❌ " + result.error);
}else{
    alert("✅ " + result.message);
}
}