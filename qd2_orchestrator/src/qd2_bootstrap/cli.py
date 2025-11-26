import typer
from qd2_bootstrap.utils.logging import setup_logging
from qd2_bootstrap.commands import infra, cluster, quditto

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.add_typer(infra.app, name="infra")
app.add_typer(cluster.app, name="cluster")
app.add_typer(quditto.app, name="quditto")

@app.callback()
def main(verbose: int = typer.Option(0, "--verbose", "-v", count=True)):
    setup_logging(verbosity=verbose)

def run():
    app()

if __name__ == "__main__":
    run()
