import { createSelector } from "reselect";
import Settings from "metabase/lib/settings";

export const getAlert = createSelector(
  [({ alerts }) => alerts, ({ params: { alertId } }) => parseInt(alertId)],
  (alerts, alertId) => {
    return alerts.find(alert => alert.id === alertId);
  },
);

export const getNotifications = createSelector(
  [({ alerts }) => alerts, ({ pulses }) => pulses],
  (alerts, pulses) => {
    const items = [
      ...alerts.map(alert => ({
        item: alert,
        type: "alert",
      })),
      ...pulses.map(pulse => ({
        item: pulse,
        type: "pulse",
      })),
    ];

    return items.sort((a, b) => b.item.created_at - a.item.created_at);
  },
);

export const getAdminEmail = () => {
  return Settings.get("admin-email");
};
