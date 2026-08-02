import asyncio

from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport
from shared.llm import ask_gemini

async def main():

    transport = StreamableHttpTransport(
        url="http://127.0.0.1:8000/mcp"
    )

    async def progress_handler(*args):
        print("Progress update:", args)


    async def sampling_callback(*args):

        message = args[1]

        prompt = message.messages[0].content.text

        response = await asyncio.to_thread(
            ask_gemini,
            prompt
        )

        return response

    
    async with Client(
        transport,
        progress_handler=progress_handler,
        sampling_handler=sampling_callback
    ) as client:

        tools = await client.list_tools()

        print("Available tools:")
        for tool in tools:
            print("-", tool.name)

        while True:

            print("\n====== CyberSecurity Agent ======")
            print("1. User History")
            print("2. IP Reputation")
            print("3. Block IP")
            print("4. Close Incident")
            print("5. Escalate Incident")
            print("6. Send Email")
            print("7. Generate Security Report")
            print("0. Exit")

            choice = input("Choose: ")

            if choice == "1":

                result = await client.call_tool(
                    "user_history",
                    {
                        "user": "Mariem Gaber"
                    }
                )

            elif choice == "2":

                result = await client.call_tool(
                    "ip_reputation",
                    {
                        "ip": "192.168.1.50"
                    }
                )

            elif choice == "3":

                result = await client.call_tool(
                    "block",
                    {
                        "request": {
                            "ip": "10.0.0.15",
                            "admin_id": 2
                        }
                    }
                )

            elif choice == "4":

                result = await client.call_tool(
                    "close",
                    {
                        "incident_id": 1,
                        "admin_id": 2
                    }
                )

            elif choice == "5":

                result = await client.call_tool(
                    "escalate",
                    {
                        "incident_id": 1
                    }
                )

            elif choice == "6":

                result = await client.call_tool(
                    "email",
                    {
                        "user": "Mariem Gaber"
                    }
                )

            elif choice == "7":

                result = await client.call_tool(
                    "security_report",
                    {
                        "days": 30
                    }
                )

            elif choice == "0":
                break

            else:
                print("Invalid choice")
                continue

            print(result.data)


if __name__ == "__main__":
    asyncio.run(main())