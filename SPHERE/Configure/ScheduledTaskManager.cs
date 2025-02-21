using SPHERE.Blockchain;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static SPHERE.Configure.CleanupTasks;
using SPHERE.Configure.Logging;

namespace SPHERE.Configure
{
    /// <summary>
    ///  This class is responsible for managing scheduled tasks.
    /// </summary>
    internal class ScheduledTaskManager
    {
        
        private CancellationTokenSource _cts =new();
        private readonly List<Task> _runningTasks = new();
        internal List<ScheduledTask> _tasks = new();

        public class ScheduledTask
        {
            // The task delegate to execute periodically.
            public required Func<CancellationToken, Task> TaskFunc { get; set; }
            // The interval at which to run the task.
            public TimeSpan Interval { get; set; }
            // Optionally, a name for logging/debugging.
            public string Name { get; set; } = "";
        }

        // AutoStartCleanUpTasks is a method that starts all the cleanup tasks on startup
        internal async Task AutoStartCleanUpTasks(Node node)
        {
            foreach (StartupTasks task in Enum.GetValues(typeof(StartupTasks)))
            {
                SystemLogger.Log(task.ToString());

                if (TaskMap.TryGetValue(task, out var taskFunc))
                {
                    
                    TimeSpan interval = CleanupTasks.TaskIntervals.TryGetValue(task, out TimeSpan taskInterval)
                                          ? taskInterval
                                          : TimeSpan.FromHours(24); // Fall back interval if not found

                    AddTask(new ScheduledTask
                    {
                        Name = task.ToString(),
                        Interval = interval,
                        TaskFunc = async (ct) =>
                        {
                            await taskFunc(node, ct);
                        }
                    });
                }
                else
                {
                    SystemLogger.Log($"No task found for: {task}");
                }
            }


            Start();
            await Task.CompletedTask;
        }   

        // Adds a new scheduled task to the manager.
        public void AddTask(ScheduledTask scheduledTask)
        {
            _tasks.Add(scheduledTask);
        }

        // Starts all scheduled tasks.
        public void Start()
        {
            _cts = new CancellationTokenSource();
            foreach (var scheduledTask in _tasks)
            {
                // Start each task as a separate asynchronous loop.
                _runningTasks.Add(RunScheduledTask(scheduledTask, _cts.Token));
            }
        }

        // Stops all scheduled tasks gracefully.
        public async Task StopAsync()
        {
            if (_cts != null)
            {
                _cts.Cancel();
                await Task.WhenAll(_runningTasks);
            }
        }

        // Runs a scheduled task in a loop until cancellation is requested.
        private async Task RunScheduledTask(ScheduledTask scheduledTask, CancellationToken cancellationToken)
        {
            // Optional initial delay can be added here if needed.
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await scheduledTask.TaskFunc(cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    // Task was cancelled; break out of the loop.
                    break;
                }
                catch (Exception ex)
                {
                    SystemLogger.Log($"Error in task '{scheduledTask.Name}': {ex.Message}");
                    // Decide whether to continue running the task or break.
                }
                // Wait for the specified interval before running again.
                try
                {
                    await Task.Delay(scheduledTask.Interval, cancellationToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }


    }
}
