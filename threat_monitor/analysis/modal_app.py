import subprocess

import modal

from threat_monitor.analysis import MODEL_REVISION


MODEL_NAME = "Qwen/Qwen3-32B"
MODEL_ALIAS = f"{MODEL_NAME}@{MODEL_REVISION}"
CONTEXT_LENGTH = 8192

if modal.is_local():
    from threat_monitor.config import get_settings

    settings = get_settings()
    if (
        settings.analysis_model != MODEL_NAME
        or settings.analysis_model_revision not in (None, MODEL_REVISION)
        or settings.analysis_context_length != CONTEXT_LENGTH
        or settings.modal_gpu != "H100"
    ):
        raise ValueError("This deployment requires the pinned Qwen3-32B revision, H100 and 8192-token context")

image = (
    modal.Image.from_registry("nvidia/cuda:12.9.0-devel-ubuntu22.04", add_python="3.12")
    .entrypoint([])
    .uv_pip_install("vllm==0.21.0", "transformers==5.8.1")
    .env({"HF_XET_HIGH_PERFORMANCE": "1"})
)
weights = modal.Volume.from_name("junction-qwen3-weights", create_if_missing=True)
compilation = modal.Volume.from_name("junction-qwen3-compilation", create_if_missing=True)
app = modal.App("junction-company-analysis")


def server_command():
    return [
        "vllm", "serve", MODEL_NAME,
        "--revision", MODEL_REVISION,
        "--tokenizer", MODEL_NAME,
        "--tokenizer-revision", MODEL_REVISION,
        "--served-model-name", MODEL_ALIAS,
        "--dtype", "bfloat16",
        "--tensor-parallel-size", "1",
        "--max-model-len", str(CONTEXT_LENGTH),
        "--max-num-seqs", "1",
        "--max-num-batched-tokens", str(CONTEXT_LENGTH),
        "--gpu-memory-utilization", "0.9",
        "--enforce-eager",
        "--enable-auto-tool-choice",
        "--tool-call-parser", "hermes",
        "--default-chat-template-kwargs", '{"enable_thinking": false}',
        "--generation-config", "vllm",
        "--host", "0.0.0.0", "--port", "8000",
    ]


@app.server(
    image=image,
    gpu="H100:1",
    port=8000,
    routing_region="eu-west",
    min_containers=0,
    max_containers=1,
    target_concurrency=1,
    max_concurrency=1,
    scaledown_window=300,
    startup_timeout=900,
    unauthenticated=False,
    volumes={"/root/.cache/huggingface": weights, "/root/.cache/vllm": compilation},
)
class QwenServer:
    @modal.enter()
    def start(self):
        self.process = subprocess.Popen(server_command())

    @modal.exit()
    def stop(self):
        self.process.terminate()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
