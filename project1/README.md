# CyberSecurity Agent

## Unconstrained ReAct Agent

### Description
This agent uses an LLM to reason freely about the alert and decide which tool to call next. It is not restricted by a schema or a predefined workflow.

### Features
- Uses an LLM for reasoning.
- Chooses tools dynamically.
- Can perform multiple reasoning steps.
- Stops when it decides the investigation is complete.

### Workflow
1. Receive a security alert.
2. Send the alert to the LLM.
3. Parse the returned action.
4. Execute the selected tool.
5. Send the observation back to the LLM.
6. Repeat until the model returns a final answer.

---

## Constrained ReAct Agent

### Description
This agent follows the same ReAct loop but adds constraints to make the behavior safer and more predictable.

### Features
- JSON-only responses.
- Pydantic schema validation.
- Allow-list of permitted tools.
- Maximum reasoning steps (`MAX_STEPS = 6`).
- Explicit `final_answer` action.

### Workflow
1. Receive a security alert.
2. Ask the LLM for the next action.
3. Validate the JSON response using Pydantic.
4. Verify that the requested tool is in the allow-list.
5. Execute the tool.
6. Send the observation back to the LLM.
7. Repeat until `final_answer` is returned or `MAX_STEPS` is reached.