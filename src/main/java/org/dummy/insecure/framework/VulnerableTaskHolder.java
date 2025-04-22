package org.dummy.insecure.framework;

import java.io.ObjectInputStream;
import java.io.Serializable;
import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;

@Slf4j
// TODO move back to lesson
public class VulnerableTaskHolder implements Serializable {

  private static final long serialVersionUID = 2;

  private String taskName;
  private String taskAction;
  private LocalDateTime requestedExecutionTime;

  public VulnerableTaskHolder(String taskName, String taskAction) {
    super();
    this.taskName = taskName;
    this.taskAction = taskAction;
    this.requestedExecutionTime = LocalDateTime.now();
  }

  @Override
  public String toString() {
    return "VulnerableTaskHolder [taskName="
        + taskName
        + ", taskAction="
        + taskAction
        + ", requestedExecutionTime="
        + requestedExecutionTime
        + "]";
  }

  /**
   * Safe implementation of readObject that does not execute external commands.
   * Deserializes the object data but does not perform any dangerous operations.
   *
   * @param stream the ObjectInputStream to read data from
   * @throws Exception if deserialization fails
   */
  private void readObject(ObjectInputStream stream) throws Exception {
    // Standard deserialization to restore object state
    stream.defaultReadObject();

    // Log information about the deserialized object
    log.info("Deserializing task: {}", taskName);
    log.info("Deserialization time: {}", LocalDateTime.now());
    log.info("Original requested execution time: {}", requestedExecutionTime);

    // Validate time constraints if needed
    if (requestedExecutionTime != null
        && (requestedExecutionTime.isBefore(LocalDateTime.now().minusMinutes(10))
            || requestedExecutionTime.isAfter(LocalDateTime.now()))) {
      log.debug(this.toString());
      throw new IllegalArgumentException("Task execution time outside allowed window");
    }

    // Log attempt to execute a command, but don't actually execute it
    if ((taskAction != null) && (taskAction.startsWith("sleep") || taskAction.startsWith("ping"))) {
      log.warn("Command execution in deserialization blocked for security: {}", taskAction);
    }
  }
}
