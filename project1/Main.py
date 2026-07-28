from constrained_react.main import main as constrained_main
from unconstrained_react.main import main as unconstrained_main
from routing.main import main as routing_main
from reactive.main import main as reactive_main


def main():

    print("\n" + "=" * 80)
    print("CONSTRAINED REACT")
    print("=" * 80)

    constrained_main()

    print("\n" + "=" * 80)
    print("UNCONSTRAINED REACT")
    print("=" * 80)

    unconstrained_main()

    print("\n" + "=" * 80)
    print("ROUTING AGENT")
    print("=" * 80)

    routing_main()

    print("\n" + "=" * 80)
    print("REACTIVE AGENT")
    print("=" * 80)

    reactive_main()


if __name__ == "__main__":
    main()