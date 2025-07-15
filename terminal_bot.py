import logging
from logging_config import setup_logging
from error_handler import ErrorHandler

# Set up logging and error handler
logger = setup_logging()
error_handler = ErrorHandler()

def process_command(command: str) -> str:
    # Replace this with your actual bot's logic
    try:
        # Example logic: just echo back for now
        return f"You typed: {command}"
    except Exception as e:
        logger.error(f"Error processing command '{command}': {e}")
        return "An error occurred. Please check the logs."

def main():
    logger.info("OSINT Bot Terminal Interface started.")
    print("Welcome to the OSINT Bot Terminal!")
    print("Type 'exit' or 'quit' to stop the bot.")
    while True:
        try:
            user_input = input(">> ")
            if user_input.lower() in ["exit", "quit"]:
                print("Goodbye!")
                logger.info("User exited terminal interface.")
                break
            # Use the error handler for processing commands
            response = error_handler.safe_execute(process_command, user_input)
            print(response)
        except KeyboardInterrupt:
            print("\nGoodbye!")
            logger.info("User interrupted terminal interface.")
            break
        except Exception as e:
            logger.critical(f"Fatal error in terminal loop: {e}")

if __name__ == "__main__":
    main()