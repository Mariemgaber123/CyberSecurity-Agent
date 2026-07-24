from unconstrained_react.agent import run_agent
from shared.test_cases import test_cases


def main():

    for case in test_cases:

        print("\n" + "=" * 60)
        print("Running Test Case:", case["name"])
        print("=" * 60)

        run_agent(case["alert"])

        print()


if __name__ == "__main__":
    main()