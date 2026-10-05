import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell
} from "recharts";

function AttackChart({ data }) {
  const colors = [
    "#3B82F6", // Blue
    "#8B5CF6", // Purple
    "#06B6D4", // Cyan
    "#EC4899", // Pink
    "#F59E0B", // Orange
    "#22C55E", // Green
    "#EF4444", // Red
    "#14B8A6", // Teal
    "#6366F1", // Indigo
    "#F97316"  // Orange-red
  ];

  return (
    <div className="chart-card">
      <div className="chart-header">
        <h2>Attack Statistics</h2>
        <span>Detected attacks</span>
      </div>

      <div className="chart-container">
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={data}>

            <CartesianGrid
              stroke="#252d4a"
              strokeDasharray="3 3"
              vertical={false}
            />

            <XAxis
              dataKey="name"
              tick={{
                fill: "#a5acc5",
                fontSize: 12
              }}
              axisLine={{
                stroke: "#303858"
              }}
              tickLine={false}
            />

            <YAxis
              tick={{
                fill: "#a5acc5",
                fontSize: 12
              }}
              axisLine={false}
              tickLine={false}
            />

            <Tooltip
              contentStyle={{
                backgroundColor: "#11172a",
                border: "1px solid #39446f",
                borderRadius: "8px",
                color: "#f5f7ff"
              }}
              labelStyle={{
                color: "#ffffff"
              }}
              itemStyle={{
                color: "#c4b5fd"
              }}
              cursor={{
                fill: "rgba(99, 102, 241, 0.08)"
              }}
            />

            <Bar
              dataKey="count"
              radius={[6, 6, 0, 0]}
            >
              {data.map((entry, index) => (
                <Cell
                  key={`cell-${index}`}
                  fill={colors[index % colors.length]}
                />
              ))}
            </Bar>

          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default AttackChart;