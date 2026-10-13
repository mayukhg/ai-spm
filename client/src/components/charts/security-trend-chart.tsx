import { useQuery } from "@tanstack/react-query";
import { Skeleton } from "@/components/ui/skeleton";
import { 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend 
} from "recharts";
import type { TimeSeriesData } from "@/types";

export default function SecurityTrendChart() {
  const { data = [], isLoading } = useQuery<TimeSeriesData[]>({
    queryKey: ["/api/dashboard/trend"],
  });

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-background border border-border rounded-lg shadow-lg p-3">
          <p className="font-medium text-foreground mb-2">{label}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {entry.name}: {entry.value}
              {entry.dataKey === 'securityScore' || entry.dataKey === 'compliance' ? '%' : ''}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  if (isLoading) {
    return (
      <div className="h-64 w-full">
        <Skeleton className="h-full w-full" />
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart
          data={data}
          margin={{
            top: 5,
            right: 30,
            left: 20,
            bottom: 5,
          }}
        >
          <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
          <XAxis 
            dataKey="timestamp" 
            className="text-muted-foreground"
            fontSize={12}
          />
          <YAxis 
            className="text-muted-foreground"
            fontSize={12}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend 
            wrapperStyle={{ 
              fontSize: '12px',
              color: 'hsl(var(--muted-foreground))'
            }}
          />
          <Line
            type="monotone"
            dataKey="securityScore"
            stroke="hsl(var(--primary))"
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Security Score"
            activeDot={{ r: 5 }}
          />
          <Line
            type="monotone"
            dataKey="compliance"
            stroke="hsl(142 76% 36%)" // Green
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Compliance"
            activeDot={{ r: 5 }}
          />
          <Line
            type="monotone"
            dataKey="vulnerabilities"
            stroke="hsl(25 95% 53%)" // Orange
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Vulnerabilities"
            activeDot={{ r: 5 }}
          />
          <Line
            type="monotone"
            dataKey="threats"
            stroke="hsl(0 84% 60%)" // Red
            strokeWidth={2}
            dot={{ r: 3 }}
            name="Active Threats"
            activeDot={{ r: 5 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
