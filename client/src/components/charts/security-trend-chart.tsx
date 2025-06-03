import { useEffect, useState } from "react";
import { Card } from "@/components/ui/card";
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
import { format, subDays } from "date-fns";
import type { TimeSeriesData } from "@/types";

// Generate sample time series data for the chart
// In a real application, this would come from an API endpoint
const generateTimeSeriesData = (): TimeSeriesData[] => {
  const data: TimeSeriesData[] = [];
  const now = new Date();
  
  for (let i = 29; i >= 0; i--) {
    const date = subDays(now, i);
    data.push({
      timestamp: format(date, "MMM dd"),
      securityScore: Math.floor(Math.random() * 20) + 75, // 75-95
      vulnerabilities: Math.floor(Math.random() * 15) + 5, // 5-20
      threats: Math.floor(Math.random() * 8) + 2, // 2-10
      compliance: Math.floor(Math.random() * 15) + 80, // 80-95
    });
  }
  
  return data;
};

export default function SecurityTrendChart() {
  const [data, setData] = useState<TimeSeriesData[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Simulate loading time
    const timer = setTimeout(() => {
      setData(generateTimeSeriesData());
      setIsLoading(false);
    }, 1000);

    return () => clearTimeout(timer);
  }, []);

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
