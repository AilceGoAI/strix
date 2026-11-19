package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Agents graph (agents_graph_renderer.py)
// ---------------------------------------------------------------------------

func renderAgentGraphTool(name string, args map[string]any, result any) string {
	var b strings.Builder
	switch name {
	case "view_agent_graph":
		b.WriteString(Col(Lavender).Render("◇ ") + Dim().Render("查看智能体关系图"))
	case "create_agent":
		agentName := StringValue(args["name"])
		if agentName == "" {
			agentName = "智能体"
		}
		b.WriteString(Col(Lavender).Render("◈ ") + Dim().Render("正在派生 ") + Bold(Lavender).Render(agentName))
		if task := StringValue(args["task"]); task != "" {
			b.WriteString("\n  " + Dim().Render(task))
		}
	case "send_message_to_agent":
		b.WriteString(Col(InfoBlue).Render("→ "))
		if target := StringValue(args["target_agent_id"]); target != "" {
			b.WriteString(Dim().Render("发送给 " + target))
		} else {
			b.WriteString(Dim().Render("正在发送消息"))
		}
		if msg := StringValue(args["message"]); msg != "" {
			b.WriteString("\n  " + Dim().Render(msg))
		}
	case "agent_finish":
		success := true
		if v, ok := args["success"].(bool); ok {
			success = v
		}
		if success {
			b.WriteString(Col(Green).Render("◆ ") + Bold(Green).Render("智能体已完成"))
		} else {
			b.WriteString(Col(Red).Render("◆ ") + Bold(Red).Render("智能体失败"))
		}
		if summary := StringValue(args["result_summary"]); summary != "" {
			b.WriteString("\n  " + lipgloss.NewStyle().Bold(true).Render(summary))
			if findings, ok := args["findings"].([]any); ok {
				for _, f := range findings {
					b.WriteString("\n  • " + Dim().Render(StringValue(f)))
				}
			}
		} else {
			b.WriteString("\n  " + Dim().Render("正在完成任务…"))
		}
	case "wait_for_agents":
		// The chat pane animates the marker while the agent is parked here.
		b.WriteString(Col(Gray).Render(SpinnerMarker+" ") + Dim().Render("等待中"))
		if reason := StringValue(args["reason"]); reason != "" {
			b.WriteString("\n  " + Dim().Render(reason))
		}
	case "stop_agent":
		b.WriteString(Col(Red).Render("◼ ") + Dim().Render("正在停止"))
		if target := StringValue(args["target_agent_id"]); target != "" {
			b.WriteString(Bold(Red).Render(" " + target))
		}
		cascade := true
		if v, ok := args["cascade"].(bool); ok {
			cascade = v
		}
		if cascade {
			b.WriteString(Dim().Italic(true).Render(" + 全部派生智能体"))
		}
		if reason := StringValue(args["reason"]); reason != "" {
			b.WriteString("\n  " + Dim().Render(reason))
		}
		if m, ok := result.(map[string]any); ok {
			if s, hs := m["success"].(bool); hs && !s {
				if e := StringValue(m["error"]); e != "" {
					b.WriteString("\n  " + Col(Red).Render(e))
				}
			}
		}
	}
	return b.String()
}
